"""
secure_user_data.py

Requirements:
    pip install cryptography bcrypt

Environment Variables:
    APP_ENCRYPTION_KEY=<fernet_key>

Generate a key once and store it securely:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Security Features:
    - Input validation
    - Authenticated encryption using Fernet (AES-128-CBC + HMAC)
    - Password hashing with bcrypt
    - Parameterized SQL queries
    - No hardcoded secrets
    - Safe defaults
"""

import os
import sqlite3
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet, InvalidToken


# =============================================================================
# Configuration
# =============================================================================

MAX_DATA_SIZE = 10_000


def get_encryption_key() -> bytes:
    """
    Retrieve encryption key from environment.

    Raises:
        RuntimeError: If key is not configured.
    """
    key = os.getenv("APP_ENCRYPTION_KEY")

    if not key:
        raise RuntimeError(
            "APP_ENCRYPTION_KEY is not set. "
            "Store a Fernet key in an environment variable."
        )

    return key.encode("utf-8")


# =============================================================================
# Validation
# =============================================================================

def validate_text(value: str, field_name: str = "input") -> str:
    """
    Validate user-supplied text input.
    """

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{field_name} cannot be empty")

    if len(value) > MAX_DATA_SIZE:
        raise ValueError(
            f"{field_name} exceeds maximum length of {MAX_DATA_SIZE}"
        )

    return value


# =============================================================================
# Encryption / Decryption
# =============================================================================

def encrypt_data(plaintext: str) -> str:
    """
    Encrypt sensitive user data.

    Args:
        plaintext: Data to encrypt.

    Returns:
        Encrypted string token.
    """
    plaintext = validate_text(plaintext, "plaintext")

    cipher = Fernet(get_encryption_key())

    encrypted = cipher.encrypt(
        plaintext.encode("utf-8")
    )

    return encrypted.decode("utf-8")


def decrypt_data(token: str) -> str:
    """
    Decrypt previously encrypted data.

    Args:
        token: Encrypted token.

    Returns:
        Original plaintext.
    """
    token = validate_text(token, "token")

    cipher = Fernet(get_encryption_key())

    try:
        decrypted = cipher.decrypt(
            token.encode("utf-8")
        )
    except InvalidToken as exc:
        raise ValueError("Invalid or tampered encrypted data") from exc

    return decrypted.decode("utf-8")


# =============================================================================
# Password Hashing
# =============================================================================

def hash_password(password: str) -> str:
    """
    Hash passwords using bcrypt.
    """
    password = validate_text(password, "password")

    if len(password) < 12:
        raise ValueError(
            "Password must be at least 12 characters long"
        )

    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    )

    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify supplied password against stored hash.
    """
    password = validate_text(password, "password")
    password_hash = validate_text(password_hash, "password_hash")

    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    )


# =============================================================================
# Database Layer (Parameterized Queries)
# =============================================================================

def initialize_database(db_path: str = "users.db") -> None:
    """
    Create database schema if missing.
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                encrypted_data TEXT NOT NULL
            )
        """)
        conn.commit()


def create_user(
    username: str,
    password: str,
    sensitive_data: str,
    db_path: str = "users.db"
) -> None:
    """
    Create a user record using:
      - bcrypt password hashing
      - encrypted sensitive data
      - parameterized SQL queries
    """
    username = validate_text(username, "username")
    sensitive_data = validate_text(
        sensitive_data,
        "sensitive_data"
    )

    password_hash = hash_password(password)
    encrypted_data = encrypt_data(sensitive_data)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, encrypted_data)
            VALUES (?, ?, ?)
            """,
            (
                username,
                password_hash,
                encrypted_data,
            ),
        )
        conn.commit()


def get_user_sensitive_data(
    username: str,
    db_path: str = "users.db"
) -> Optional"""
    Retrieve and decrypt sensitive data.
    """
    username = validate_text(username, "username")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT encrypted_data
            FROM users
            WHERE username = ?
            """,
            (username,),
        )

        row = cursor.fetchone()

    if row is None:
        return None

    return decrypt_data(row[0])


def authenticate_user(
    username: str,
    password: str,
    db_path: str = "users.db"
) -> bool:
    """
    Authenticate user credentials.
    """
    username = validate_text(username, "username")
    password = validate_text(password, "password")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        )

        row = cursor.fetchone()

    if row is None:
        return False

    return verify_password(password, row[0])


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    initialize_database()

    try:
        create_user(
            username="alice",
            password="VeryStrongPassword123!",
            sensitive_data="SSN: 123-45-6789"
        )
    except sqlite3.IntegrityError:
        pass

    authenticated = authenticate_user(
        "alice",
        "VeryStrongPassword123!"
    )

    print(f"Authenticated: {authenticated}")

    if authenticated:
        secret = get_user_sensitive_data("alice")
        print(f"Decrypted data: {secret}")