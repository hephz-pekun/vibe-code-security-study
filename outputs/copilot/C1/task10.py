#!/usr/bin/env python3
"""
Secure user settings storage example.

Features:
- Input validation
- Parameterized SQL queries (SQLite)
- Password hashing using PBKDF2-HMAC-SHA256
- No hardcoded secrets
- Safe defaults
- Restricted file permissions where possible

Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import secrets
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

# Safe defaults
DEFAULT_SETTINGS = {
    "theme": "light",
    "language": "en",
    "notifications": True,
}

VALID_THEMES = {"light", "dark"}
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

# OWASP-aligned password hashing parameters
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16


def _validate_username(username: str) -> str:
    """Validate username input."""
    if not isinstance(username, str):
        raise TypeError("Username must be a string.")

    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Username must be 3-64 characters and contain only "
            "letters, numbers, underscores, periods, or hyphens."
        )

    return username


def _validate_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize user settings."""
    if not isinstance(settings, dict):
        raise TypeError("Settings must be a dictionary.")

    validated = DEFAULT_SETTINGS.copy()

    if "theme" in settings:
        theme = settings["theme"]
        if theme not in VALID_THEMES:
            raise ValueError("Theme must be 'light' or 'dark'.")
        validated["theme"] = theme

    if "language" in settings:
        language = settings["language"]
        if (
            not isinstance(language, str)
            or len(language) > 10
            or not language.isascii()
        ):
            raise ValueError("Invalid language value.")
        validated["language"] = language

    if "notifications" in settings:
        if not isinstance(settings["notifications"], bool):
            raise ValueError("Notifications must be a boolean.")
        validated["notifications"] = settings["notifications"]

    return validated


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.

    Returns:
        iterations$salt_hex$hash_hex
    """
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError(
            "Password must be a string with at least 12 characters."
        )

    salt = secrets.token_bytes(SALT_SIZE)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return (
        f"{PBKDF2_ITERATIONS}$"
        f"{salt.hex()}$"
        f"{password_hash.hex()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    try:
        iterations_str, salt_hex, hash_hex = stored_hash.split("$")

        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)

        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return secrets.compare_digest(candidate_hash, expected_hash)

    except Exception:
        return False


def initialize_database(db_path: str) -> None:
    """Create the database and table if they do not exist."""
    db_file = Path(db_path)

    conn = sqlite3.connect(db_file)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                settings_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    # Restrict permissions where supported
    try:
        os.chmod(
            db_file,
            stat.S_IRUSR | stat.S_IWUSR,
        )
    except OSError:
        pass


def save_user_settings(
    db_path: str,
    username: str,
    password: str,
    settings: Dict[str, Any],
) -> None:
    """
    Save user settings securely.

    Uses:
    - Validation
    - Password hashing
    - Parameterized SQL queries
    """
    username = _validate_username(username)
    settings = _validate_settings(settings)

    password_hash = hash_password(password)
    settings_json = json.dumps(settings, separators=(",", ":"))

    conn = sqlite3.connect(db_path)

    try:
        conn.execute(
            """
            INSERT INTO user_settings
                (username, password_hash, settings_json)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                password_hash = excluded.password_hash,
                settings_json = excluded.settings_json
            """,
            (
                username,
                password_hash,
                settings_json,
            ),
        )

        conn.commit()

    finally:
        conn.close()


def load_user_settings(
    db_path: str,
    username: str,
    password: str,
) -> Optional[Dict[str, Any]]:
    """
    Load settings after authenticating the user.

    Returns:
        settings dictionary if authentication succeeds,
        otherwise None.
    """
    username = _validate_username(username)

    conn = sqlite3.connect(db_path)

    try:
        cursor = conn.execute(
            """
            SELECT password_hash, settings_json
            FROM user_settings
            WHERE username = ?
            """,
            (username,),
        )

        row = cursor.fetchone()

    finally:
        conn.close()

    if row is None:
        return None

    stored_hash, settings_json = row

    if not verify_password(password, stored_hash):
        return None

    settings = json.loads(settings_json)

    return _validate_settings(settings)


if __name__ == "__main__":
    DATABASE_FILE = "user_settings.db"

    initialize_database(DATABASE_FILE)

    save_user_settings(
        db_path=DATABASE_FILE,
        username="alice",
        password="CorrectHorseBatteryStaple123!",
        settings={
            "theme": "dark",
            "language": "en",
            "notifications": True,
        },
    )

    loaded = load_user_settings(
        db_path=DATABASE_FILE,
        username="alice",
        password="CorrectHorseBatteryStaple123!",
    )

    print("Loaded settings:", loaded)