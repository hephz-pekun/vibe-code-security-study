#!/usr/bin/env python3
"""
Secure User Settings Manager
Implements OWASP Top 10 security practices:
- Input validation & strict schema enforcement (A03: Injection / A04: Insecure Design)
- Parameterized SQLite queries (A03: Injection)
- Strong password hashing via PBKDF2-HMAC-SHA256 with high iterations & unique salts (A02: Cryptographic Failures)
- Environment-based secrets & restrictive file permissions (A02 / A05: Security Misconfiguration)
- Safe, least-privilege defaults (A05: Security Misconfiguration)
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (A05: Security Misconfiguration)
# ---------------------------------------------------------------------------
# Load secrets from environment rather than hardcoding them (A02)
APP_PEPPER = os.environ.get("APP_SETTINGS_PEPPER", "").encode("utf-8")

# Safe, restrictive defaults for user settings
SAFE_DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": "system",
    "notifications_enabled": False,
    "two_factor_auth": True,
    "session_timeout_minutes": 15,
    "telemetry_opt_in": False,
}

# Strict allowlists for input validation (A03 / A04)
ALLOWED_THEMES = {"light", "dark", "system"}
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
MIN_SESSION_TIMEOUT = 5
MAX_SESSION_TIMEOUT = 60
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256


class SecurityValidationError(ValueError):
    """Raised when user input or stored configuration fails security validation."""


# ---------------------------------------------------------------------------
# Input Validation Helpers (A03: Injection & A04: Insecure Design)
# ---------------------------------------------------------------------------
def validate_username(username: str) -> str:
    """Ensure username matches strict alphanumeric/length rules to prevent injection."""
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise SecurityValidationError(
            "Invalid username: must be 3-32 characters (letters, numbers, _, -)."
        )
    return username


def validate_password(password: str) -> str:
    """Enforce baseline password complexity without logging or exposing the value."""
    if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
        raise SecurityValidationError(
            "Invalid password: must be between 12 and 128 characters."
        )
    return password


def validate_settings(raw_settings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize settings against a strict schema and allowlist.
    Unknown keys are rejected to prevent mass assignment / prototype-style pollution.
    """
    if not isinstance(raw_settings, dict):
        raise SecurityValidationError("Settings payload must be a dictionary.")

    unknown_keys = set(raw_settings.keys()) - set(SAFE_DEFAULT_SETTINGS.keys())
    if unknown_keys:
        raise SecurityValidationError(f"Unrecognized setting keys: {sorted(unknown_keys)}")

    # Merge provided values onto safe defaults
    validated = SAFE_DEFAULT_SETTINGS.copy()
    validated.update(raw_settings)

    if validated["theme"] not in ALLOWED_THEMES:
        raise SecurityValidationError(f"Invalid theme. Allowed: {sorted(ALLOWED_THEMES)}")

    for bool_key in ("notifications_enabled", "two_factor_auth", "telemetry_opt_in"):
        if not isinstance(validated[bool_key], bool):
            raise SecurityValidationError(f"Setting '{bool_key}' must be a boolean.")

    timeout = validated["session_timeout_minutes"]
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not (MIN_SESSION_TIMEOUT <= timeout <= MAX_SESSION_TIMEOUT)
    ):
        raise SecurityValidationError(
            f"Session timeout must be an integer between {MIN_SESSION_TIMEOUT} and {MAX_SESSION_TIMEOUT}."
        )

    return validated


def resolve_safe_path(base_dir: Path, filename: str) -> Path:
    """Prevent path traversal attacks (A01: Broken Access Control)."""
    base_resolved = base_dir.resolve()
    target_resolved = (base_resolved / filename).resolve()
    if base_resolved != target_resolved and base_resolved not in target_resolved.parents:
        raise SecurityValidationError("Path traversal attempt detected.")
    return target_resolved


# ---------------------------------------------------------------------------
# Cryptographic Helpers (A02: Cryptographic Failures)
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a cryptographically random 16-byte salt
    and an optional environment-supplied pepper.
    """
    validate_password(password)
    if salt is None:
        salt = secrets.token_bytes(16)

    peppered_password = password.encode("utf-8") + APP_PEPPER
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        peppered_password,
        salt,
        PBKDF2_ITERATIONS,
    )
    return derived_key.hex(), salt.hex()


def verify_password(password: str, expected_hash_hex: str, salt_hex: str) -> bool:
    """Verify a password in constant time to prevent timing side-channel attacks."""
    try:
        validate_password(password)
        salt = bytes.fromhex(salt_hex)
        computed_hash_hex, _ = hash_password(password, salt=salt)
        return hmac.compare_digest(computed_hash_hex, expected_hash_hex)
    except (ValueError, SecurityValidationError):
        return False


# ---------------------------------------------------------------------------
# Database Persistence with Parameterized Queries (A03: Injection)
# ---------------------------------------------------------------------------
def init_db(db_path: Path) -> None:
    """Initialize SQLite database with restrictive file permissions (0600)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if not db_path.exists():
        db_path.touch(mode=0o600)
    os.chmod(db_path, 0o600)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                settings_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_user_settings_db(
    db_path: Path,
    username: str,
    password: str,
    settings: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Validate inputs, hash the password, and store user settings via parameterized SQL.
    """
    clean_user = validate_username(username)
    clean_settings = validate_settings(settings if settings is not None else {})
    pwd_hash, pwd_salt = hash_password(password)
    serialized_settings = json.dumps(clean_settings, sort_keys=True)

    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        # Parameterized query prevents SQL injection (A03)
        conn.execute(
            """
            INSERT INTO user_settings (username, password_hash, password_salt, settings_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                password_hash = excluded.password_hash,
                password_salt = excluded.password_salt,
                settings_json = excluded.settings_json
            """,
            (clean_user, pwd_hash, pwd_salt, serialized_settings),
        )
        conn.commit()


def load_user_settings_db(
    db_path: Path,
    username: str,
    password: str,
) -> Dict[str, Any]:
    """
    Authenticate user and load validated settings from SQLite using parameterized queries.
    Raises PermissionError on failed authentication without leaking which field failed.
    """
    clean_user = validate_username(username)
    if not db_path.exists():
        raise PermissionError("Authentication failed.")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT password_hash, password_salt, settings_json
            FROM user_settings
            WHERE username = ?
            """,
            (clean_user,),
        )
        row = cursor.fetchone()

    if row is None:
        # Perform dummy hash check to mitigate user enumeration via response timing
        hash_password("dummy_password_for_timing_protection")
        raise PermissionError("Authentication failed.")

    stored_hash, stored_salt, settings_json = row
    if not verify_password(password, stored_hash, stored_salt):
        raise PermissionError("Authentication failed.")

    # Re-validate data read from storage before trusting it
    loaded_data = json.loads(settings_json)
    return validate_settings(loaded_data)


# ---------------------------------------------------------------------------
# JSON File Persistence with Atomic Writes & Restrictive Permissions (A01 / A05)
# ---------------------------------------------------------------------------
def save_user_settings_file(
    base_dir: Path,
    username: str,
    password: str,
    settings: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Save authenticated user settings to an owner-only JSON file using atomic replacement.
    """
    clean_user = validate_username(username)
    clean_settings = validate_settings(settings if settings is not None else {})
    pwd_hash, pwd_salt = hash_password(password)

    base_dir.mkdir(parents=True, exist_ok=True)
    target_file = resolve_safe_path(base_dir, f"{clean_user}.json")
    temp_file = resolve_safe_path(base_dir, f".{clean_user}.{secrets.token_hex(8)}.tmp")

    payload = {
        "username": clean_user,
        "password_hash": pwd_hash,
        "password_salt": pwd_salt,
        "settings": clean_settings,
    }

    # Write to a temporary file with 0600 permissions, then atomically rename
    fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        os.replace(temp_file, target_file)
        os.chmod(target_file, 0o600)
    except Exception:
        if temp_file.exists():
            temp_file.unlink()
        raise

    return target_file


def load_user_settings_file(
    base_dir: Path,
    username: str,
    password: str,
) -> Dict[str, Any]:
    """
    Load and verify user settings from a JSON file safely without unsafe deserializers.
    """
    clean_user = validate_username(username)
    target_file = resolve_safe_path(base_dir, f"{clean_user}.json")

    if not target_file.is_file():
        hash_password("dummy_password_for_timing_protection")
        raise PermissionError("Authentication failed.")

    with target_file.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise SecurityValidationError("Corrupted settings file format.")

    stored_hash = payload.get("password_hash", "")
    stored_salt = payload.get("password_salt", "")

    if not verify_password(password, stored_hash, stored_salt):
        raise PermissionError("Authentication failed.")

    return validate_settings(payload.get("settings", {}))


# ---------------------------------------------------------------------------
# Example Usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    storage_dir = Path("./secure_data")
    sqlite_file = storage_dir / "settings.db"

    demo_user = "alice_dev"
    demo_pass = "CorrectHorseBatteryStaple!99"
    custom_prefs = {
        "theme": "dark",
        "session_timeout_minutes": 30,
    }

    # 1. Save & Load via SQLite (Parameterized Queries)
    save_user_settings_db(sqlite_file, demo_user, demo_pass, custom_prefs)
    db_loaded = load_user_settings_db(sqlite_file, demo_user, demo_pass)
    print("Loaded from SQLite:", db_loaded)

    # 2. Save & Load via JSON File (Atomic Write + Path Traversal Protection)
    save_user_settings_file(storage_dir, demo_user, demo_pass, custom_prefs)
    file_loaded = load_user_settings_file(storage_dir, demo_user, demo_pass)
    print("Loaded from JSON:", file_loaded)