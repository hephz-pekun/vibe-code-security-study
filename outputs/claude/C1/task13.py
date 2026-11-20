"""
secure_user_data.py

Encrypt / decrypt user data and manage users securely.

Security design (mapped to OWASP Top 10):
  A01 Broken Access Control    -> data is bound to a user via AEAD associated data;
                                  every query is scoped by user_id.
  A02 Cryptographic Failures   -> AES-256-GCM (authenticated encryption), random
                                  96-bit nonce per message, Argon2id for passwords,
                                  keys come from the environment, never from code.
  A03 Injection                -> parameterized SQL only; strict input validation.
  A04 Insecure Design          -> versioned ciphertext format (enables key/algorithm
                                  migration), size limits, safe defaults.
  A05 Security Misconfiguration-> SQLite foreign keys on, restrictive file mode,
                                  no debug output, no secrets in logs.
  A07 Auth Failures            -> strong password policy, Argon2id with rehash-on-login,
                                  uniform error messages, timing-equalized lookups.
  A09 Logging Failures         -> logs events, never secrets or plaintext.

Dependencies:
    pip install cryptography argon2-cffi

Key setup (generate once, store in a secrets manager / env var, NOT in source):
    python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
    export USER_DATA_KEY="<output of the command above>"
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from typing import Iterator, Optional, Union

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("secure_user_data")
logger.addHandler(logging.NullHandler())

# --------------------------------------------------------------------------- #
# Constants / safe defaults
# --------------------------------------------------------------------------- #
KEY_ENV_VAR = "USER_DATA_KEY"          # secret is read from the environment
KEY_SIZE = 32                           # 256-bit AES key
NONCE_SIZE = 12                         # 96-bit nonce recommended for GCM
FORMAT_VERSION = b"\x01"                # lets you migrate algorithms/keys later
MAX_PLAINTEXT_BYTES = 64 * 1024         # cap input size (DoS protection)
MAX_TOKEN_CHARS = 2 * MAX_PLAINTEXT_BYTES  # cap ciphertext size before decoding

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128                  # prevents hashing-based DoS

# Argon2id, parameters at or above OWASP's minimum recommendation
# (m=19 MiB, t=2, p=1). Tune upward for your hardware.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,   # KiB -> 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)
# Used to equalize timing when a username does not exist.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")


class SecurityError(Exception):
    """Generic error. Messages are intentionally non-revealing."""


class ValidationError(ValueError):
    """Raised when input fails validation."""


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
def validate_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValidationError(
            "Username must be 3-32 characters: letters, digits, '_', '.', '-'."
        )
    return username


def validate_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValidationError("Password must be a string.")
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ValidationError(
            f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters."
        )
    classes = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(classes) < 3:
        raise ValidationError(
            "Password must mix at least three of: lowercase, uppercase, digits, symbols."
        )
    return password


def validate_field_name(field: str) -> str:
    if not isinstance(field, str) or not FIELD_RE.fullmatch(field):
        raise ValidationError(
            "Field name must be lowercase letters/digits/underscore, starting with a letter."
        )
    return field


def _to_bytes(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        raise ValidationError("Data must be str or bytes.")
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise ValidationError(f"Data exceeds {MAX_PLAINTEXT_BYTES} bytes.")
    return raw


# --------------------------------------------------------------------------- #
# Key handling (no hardcoded secrets)
# --------------------------------------------------------------------------- #
def load_key(env_var: str = KEY_ENV_VAR) -> bytes:
    """Load the 256-bit master key from the environment (base64url encoded)."""
    encoded = os.environ.get(env_var)
    if not encoded:
        raise SecurityError(f"Encryption key not configured (set {env_var}).")
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        raise SecurityError("Encryption key is malformed.") from None
    if len(key) != KEY_SIZE:
        raise SecurityError("Encryption key must decode to exactly 32 bytes.")
    return key


def generate_key() -> str:
    """Create a fresh random key (base64url). Store it in a secrets manager."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode("ascii")


# --------------------------------------------------------------------------- #
# Encryption / decryption (AES-256-GCM)
# --------------------------------------------------------------------------- #
def encrypt_data(
    plaintext: Union[str, bytes],
    key: bytes,
    context: str = "",
) -> str:
    """
    Encrypt data and return a URL-safe base64 token:
        base64url( version(1) || nonce(12) || ciphertext||tag )

    `context` is authenticated but not encrypted (AEAD associated data). Use it to
    bind ciphertext to its owner/field so it can't be swapped between rows/users.
    """
    if len(key) != KEY_SIZE:
        raise SecurityError("Invalid key length.")
    raw = _to_bytes(plaintext)
    nonce = os.urandom(NONCE_SIZE)  # unique per message; never reuse with the same key
    ct = AESGCM(key).encrypt(nonce, raw, context.encode("utf-8"))
    return base64.urlsafe_b64encode(FORMAT_VERSION + nonce + ct).decode("ascii")


def decrypt_data(token: str, key: bytes, context: str = "") -> bytes:
    """Decrypt a token produced by encrypt_data. Raises SecurityError on any failure."""
    if len(key) != KEY_SIZE:
        raise SecurityError("Invalid key length.")
    # One generic error for every failure mode (no oracle for attackers).
    fail = SecurityError("Decryption failed.")
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
        raise fail
    try:
        blob = base64.urlsafe_b64decode(token.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        raise fail from None
    if len(blob) < 1 + NONCE_SIZE + 16 or blob[:1] != FORMAT_VERSION:
        raise fail
    nonce = blob[1 : 1 + NONCE_SIZE]
    ct = blob[1 + NONCE_SIZE :]
    try:
        return AESGCM(key).decrypt(nonce, ct, context.encode("utf-8"))
    except InvalidTag:
        logger.warning("Decryption failed: authentication tag mismatch.")
        raise fail from None


# --------------------------------------------------------------------------- #
# Password hashing (Argon2id)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Hash a password with Argon2id (salt is generated and embedded automatically)."""
    return _hasher.hash(validate_password(password))


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time verification. Never raises on bad credentials."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LEN:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# --------------------------------------------------------------------------- #
# Database layer (parameterized queries only)
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user_data (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field_name TEXT    NOT NULL,
    token      TEXT    NOT NULL,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, field_name)
);
"""


@contextmanager
def open_db(path: str = "app.db") -> Iterator[sqlite3.Connection]:
    """Open the DB with safe defaults; commit on success, roll back on error."""
    is_new = path != ":memory:" and not os.path.exists(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(_SCHEMA)
        if is_new:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600: owner only
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def register_user(conn: sqlite3.Connection, username: str, password: str) -> int:
    """Create a user. Returns the new user id."""
    validate_username(username)
    pw_hash = hash_password(password)  # validates password policy too
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
    except sqlite3.IntegrityError:
        # Don't confirm whether the username exists beyond what's unavoidable.
        raise SecurityError("Registration failed.") from None
    logger.info("User registered (id=%s).", cur.lastrowid)
    return int(cur.lastrowid)


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> Optional[int]:
    """Return user id on success, None on failure (same response either way)."""
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        verify_password(_DUMMY_HASH, "x")  # keep timing similar
        return None
    row = conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        verify_password(_DUMMY_HASH, password)  # equalize timing
        return None
    user_id, stored = row
    if not verify_password(stored, password):
        logger.warning("Failed login attempt.")
        return None
    # Upgrade the hash transparently if parameters have been strengthened.
    if _hasher.check_needs_rehash(stored):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hasher.hash(password), user_id),
        )
    return int(user_id)


def _context(user_id: int, field: str) -> str:
    return f"user:{int(user_id)}:field:{field}"


def save_user_data(
    conn: sqlite3.Connection,
    user_id: int,
    field: str,
    value: Union[str, bytes],
    key: bytes,
) -> None:
    """Encrypt and store a value for a user (insert or update)."""
    validate_field_name(field)
    token = encrypt_data(value, key, context=_context(user_id, field))
    conn.execute(
        """
        INSERT INTO user_data (user_id, field_name, token)
        VALUES (?, ?, ?)
        ON CONFLICT (user_id, field_name)
        DO UPDATE SET token = excluded.token, updated_at = datetime('now')
        """,
        (user_id, field, token),
    )


def load_user_data(
    conn: sqlite3.Connection,
    user_id: int,
    field: str,
    key: bytes,
) -> Optional[bytes]:
    """Fetch and decrypt a user's value. Returns None if not present."""
    validate_field_name(field)
    row = conn.execute(
        "SELECT token FROM user_data WHERE user_id = ? AND field_name = ?",
        (user_id, field),
    ).fetchone()
    if row is None:
        return None
    return decrypt_data(row[0], key, context=_context(user_id, field))


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _demo() -> None:
    # For the demo ONLY, a throwaway in-memory key is created. In production, set
    # USER_DATA_KEY in your environment / secrets manager instead.
    os.environ.setdefault(KEY_ENV_VAR, generate_key())
    key = load_key()

    with open_db(":memory:") as conn:
        uid = register_user(conn, "alice", "C0rrect-Horse-Battery!")
        assert authenticate(conn, "alice", "wrong-password-123!") is None
        assert authenticate(conn, "alice", "C0rrect-Horse-Battery!") == uid

        save_user_data(conn, uid, "ssn", "123-45-6789", key)
        stored = conn.execute("SELECT token FROM user_data").fetchone()[0]
        print("Stored (encrypted):", stored[:48] + "...")
        print("Decrypted:", load_user_data(conn, uid, "ssn", key).decode())

        # Tamper / context-swap test: ciphertext is bound to its user and field.
        try:
            decrypt_data(stored, key, context=_context(uid + 1, "ssn"))
        except SecurityError as exc:
            print("Swap attack rejected:", exc)

        # Injection attempt is rejected by validation (and would be inert anyway
        # because queries are parameterized).
        try:
            authenticate(conn, "alice' OR '1'='1", "x")
            register_user(conn, "bob'; DROP TABLE users;--", "Str0ng-Passw0rd!!")
        except ValidationError as exc:
            print("Bad input rejected:", exc)


if __name__ == "__main__":
    _demo()