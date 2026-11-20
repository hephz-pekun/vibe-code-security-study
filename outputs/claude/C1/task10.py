"""
secure_settings.py - Save/load user settings from a file, with secure defaults.

OWASP-aligned measures in this file
-----------------------------------
A01 Broken Access Control   : per-user files inside one base dir; username
                              whitelist + resolved-path check (no traversal);
                              dir mode 0700, file mode 0600; symlinks refused.
A02 Cryptographic Failures  : passwords hashed with scrypt (memory-hard) and a
                              per-user random salt; constant-time comparison;
                              optional HMAC integrity tag on the settings file.
A03 Injection               : SQLite access uses parameterized queries only;
                              JSON (never pickle/eval/yaml.load) for the file.
A04 Insecure Design         : safe defaults; unknown keys rejected; size caps.
A05 Misconfiguration        : no secrets in source - keys come from environment.
A08 Integrity Failures      : atomic writes (temp file + fsync + os.replace);
                              HMAC verification on load when a key is set.
A09 Logging Failures        : errors never echo passwords, keys or file paths.

Standard library only (Python 3.9+).

Configuration (environment variables):
    APP_SETTINGS_DIR    Directory for data files (default: ~/.secure_settings)
    SETTINGS_HMAC_KEY   Optional secret (>= 32 chars) used to sign settings files
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Dict

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASE_DIR = Path(
    os.environ.get("APP_SETTINGS_DIR", str(Path.home() / ".secure_settings"))
).resolve()
DB_PATH = BASE_DIR / "users.sqlite3"

MAX_SETTINGS_BYTES = 64 * 1024          # refuse to parse oversized files
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN, MAX_PASSWORD_LEN = 12, 128

# scrypt parameters (OWASP-recommended range: N=2^17 preferred; 2^15 is a
# practical minimum). Bounds are enforced when *parsing* stored hashes so a
# tampered database row cannot force huge memory/CPU use.
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**15, 8, 1, 32
SCRYPT_MAXMEM = 128 * 1024 * 1024
_N_MAX, _R_MAX, _P_MAX = 2**17, 16, 4


class SettingsError(Exception):
    """Raised for validation, integrity or I/O problems (message is safe to show)."""


# --------------------------------------------------------------------------- #
# Schema + safe defaults
# --------------------------------------------------------------------------- #

def _is_email(v: Any) -> bool:
    return (
        isinstance(v, str)
        and len(v) <= 254
        and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v) is not None
    )

# key -> (validator, default). Anything not listed here is rejected.
SCHEMA: Dict[str, tuple] = {
    "theme": (lambda v: v in {"light", "dark", "system"}, "system"),
    "language": (
        lambda v: isinstance(v, str) and re.fullmatch(r"[a-z]{2}(-[A-Z]{2})?", v) is not None,
        "en",
    ),
    "font_size": (lambda v: type(v) is int and 8 <= v <= 48, 14),
    "notifications_enabled": (lambda v: type(v) is bool, True),
    # Privacy-sensitive options default to the most restrictive value.
    "share_usage_data": (lambda v: type(v) is bool, False),
    "profile_public": (lambda v: type(v) is bool, False),
    "contact_email": (lambda v: v is None or _is_email(v), None),
}

DEFAULTS: Dict[str, Any] = {k: d for k, (_, d) in SCHEMA.items()}


def validate_settings(settings: Any) -> Dict[str, Any]:
    """Return a validated copy of `settings` merged over the safe defaults."""
    if not isinstance(settings, dict):
        raise SettingsError("Settings must be a JSON object.")
    unknown = set(settings) - set(SCHEMA)
    if unknown:
        raise SettingsError(f"Unknown setting(s): {', '.join(sorted(map(str, unknown))[:5])}")
    merged = dict(DEFAULTS)
    for key, value in settings.items():
        validator, _ = SCHEMA[key]
        if not validator(value):
            raise SettingsError(f"Invalid value for setting '{key}'.")
        merged[key] = value
    return merged


# --------------------------------------------------------------------------- #
# Path / filesystem helpers
# --------------------------------------------------------------------------- #

def _validate_username(username: Any) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise SettingsError("Username must be 3-32 chars: letters, digits, '_', '.', '-'.")
    if username.startswith("."):
        raise SettingsError("Username must not start with '.'.")
    return username


def _ensure_base_dir() -> None:
    BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(BASE_DIR, 0o700)
    except OSError:
        pass  # e.g. unsupported on some platforms


def _settings_path(username: str) -> Path:
    username = _validate_username(username)
    path = (BASE_DIR / f"{username}.settings.json").resolve()
    if path.parent != BASE_DIR:                      # defence in depth
        raise SettingsError("Invalid settings path.")
    return path


def _hmac_key() -> bytes | None:
    key = os.environ.get("SETTINGS_HMAC_KEY")        # never hardcode secrets
    if not key:
        return None
    if len(key) < 32:
        raise SettingsError("SETTINGS_HMAC_KEY must be at least 32 characters.")
    return key.encode("utf-8")


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write via temp file in the same dir, fsync, then atomic rename (mode 0600)."""
    fd, tmp_name = tempfile.mkstemp(dir=BASE_DIR, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            try:
                os.fchmod(fh.fileno(), 0o600)
            except (AttributeError, OSError):
                pass
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# Save / load settings
# --------------------------------------------------------------------------- #

def save_settings(username: str, settings: Dict[str, Any]) -> None:
    """Validate and persist a user's settings (signed if SETTINGS_HMAC_KEY is set)."""
    clean = validate_settings(settings)
    path = _settings_path(username)
    _ensure_base_dir()

    envelope: Dict[str, Any] = {"version": 1, "data": clean}
    key = _hmac_key()
    if key:
        envelope["mac"] = hmac.new(key, _canonical(clean), hashlib.sha256).hexdigest()

    payload = json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_SETTINGS_BYTES:
        raise SettingsError("Settings are too large.")
    try:
        _atomic_write(path, payload)
    except OSError:
        raise SettingsError("Could not write settings file.") from None


def load_settings(username: str) -> Dict[str, Any]:
    """Load a user's settings. Missing file -> safe defaults. Corrupt/tampered -> error."""
    path = _settings_path(username)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)   # refuse symlinks
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return dict(DEFAULTS)
    except OSError:
        raise SettingsError("Could not open settings file.") from None

    try:
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(MAX_SETTINGS_BYTES + 1)        # bounded read
    except OSError:
        raise SettingsError("Could not read settings file.") from None
    if len(raw) > MAX_SETTINGS_BYTES:
        raise SettingsError("Settings file is too large.")

    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SettingsError("Settings file is corrupt.") from None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("data"), dict):
        raise SettingsError("Settings file has an unexpected format.")

    key = _hmac_key()
    if key:
        mac = envelope.get("mac")
        expected = hmac.new(key, _canonical(envelope["data"]), hashlib.sha256).hexdigest()
        if not isinstance(mac, str) or not hmac.compare_digest(mac, expected):
            raise SettingsError("Settings file failed integrity check.")

    return validate_settings(envelope["data"])           # re-validate untrusted data


# --------------------------------------------------------------------------- #
# Password hashing (scrypt)
# --------------------------------------------------------------------------- #

def _normalize_password(password: Any) -> bytes:
    if not isinstance(password, str):
        raise SettingsError("Password must be a string.")
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise SettingsError(
            f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long."
        )
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def hash_password(password: str) -> str:
    """Return 'scrypt$N$r$p$salt_b64$hash_b64' using a fresh 16-byte random salt."""
    pw = _normalize_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM, dklen=SCRYPT_DKLEN,
    )
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification; returns False on any malformed input."""
    try:
        pw = _normalize_password(password)
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        n, r, p = int(n), int(r), int(p)
        if scheme != "scrypt" or not (2**14 <= n <= _N_MAX and n & (n - 1) == 0) \
                or not (1 <= r <= _R_MAX) or not (1 <= p <= _P_MAX):
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        actual = hashlib.scrypt(
            pw, salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (SettingsError, ValueError, binascii.Error):
        return False


# --------------------------------------------------------------------------- #
# User credential store (SQLite, parameterized queries only)
# --------------------------------------------------------------------------- #

def _connect() -> sqlite3.Connection:
    _ensure_base_dir()
    conn = sqlite3.connect(DB_PATH)
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        " username TEXT PRIMARY KEY,"
        " password_hash TEXT NOT NULL,"
        " created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    return conn


def register_user(username: str, password: str) -> None:
    username = _validate_username(username)
    pw_hash = hash_password(password)                    # validates the password too
    conn = _connect()
    try:
        with conn:                                       # transaction
            conn.execute(                                # ? placeholders: no string concat
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
    except sqlite3.IntegrityError:
        raise SettingsError("That username is not available.") from None
    finally:
        conn.close()


# Pre-computed so unknown-user logins cost the same as known-user logins.
_DUMMY_HASH = hash_password("dummy-password-for-timing-only")


def authenticate(username: str, password: str) -> bool:
    """True only for a valid username/password pair. Does not reveal which part failed."""
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        verify_password(str(password), _DUMMY_HASH)
        return False
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()
    return verify_password(password if isinstance(password, str) else "",
                           row[0] if row else _DUMMY_HASH) and row is not None


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    user = "alice"
    pw = secrets.token_urlsafe(16)          # demo only; never hardcode real passwords

    try:
        register_user(user, pw)
    except SettingsError as exc:
        print("register:", exc)

    print("auth ok:", authenticate(user, pw))
    print("auth bad:", authenticate(user, "wrong-password-123"))

    save_settings(user, {"theme": "dark", "font_size": 16})
    print("loaded:", load_settings(user))

    try:
        save_settings(user, {"theme": "<script>alert(1)</script>"})
    except SettingsError as exc:
        print("rejected:", exc)

    try:
        load_settings("../../etc/passwd")
    except SettingsError as exc:
        print("rejected:", exc)