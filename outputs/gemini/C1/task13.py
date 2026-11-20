"""
Secure User Data Encryption & Storage Module
--------------------------------------------
Demonstrates OWASP Top 10 secure coding practices:
- A01/A03: Strict input validation and parameterized SQL queries.
- A02: Authenticated encryption (AES-256-GCM via Fernet) and Argon2id password hashing.
- A05/A07: Safe defaults, environment-sourced keys, and constant-time comparisons.

Dependencies:
    pip install cryptography argon2-cffi
"""

import os
import re
import sqlite3
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configure logging without leaking sensitive data
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants for input validation
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
MAX_PAYLOAD_BYTES = 65536  # 64 KB limit to prevent DoS via memory exhaustion


class SecurityConfigurationError(Exception):
    """Raised when required cryptographic keys are missing or invalid."""


class InputValidationError(ValueError):
    """Raised when user input fails strict validation rules."""


class CryptoManager:
    """Handles symmetric encryption/decryption and password hashing."""

    def __init__(self, encryption_key: Optional[str] = None) -> None:
        """
        Initializes the CryptoManager using an environment variable by default
        to avoid hardcoded secrets.
        """
        raw_key = encryption_key or os.environ.get("APP_ENCRYPTION_KEY")
        if not raw_key:
            raise SecurityConfigurationError(
                "Missing APP_ENCRYPTION_KEY environment variable. "
                "Generate one using: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )

        try:
            self._fernet = Fernet(raw_key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise SecurityConfigurationError("Invalid Fernet encryption key format.") from exc

        # Argon2id is the OWASP-recommended algorithm for password hashing.
        # Defaults in argon2-cffi use Argon2id with safe memory/time costs.
        self._ph = PasswordHasher()

    def encrypt_data(self, plaintext: str) -> str:
        """Validates and encrypts a UTF-8 string using authenticated encryption."""
        if not isinstance(plaintext, str) or not plaintext.strip():
            raise InputValidationError("Plaintext must be a non-empty string.")

        encoded_data = plaintext.encode("utf-8")
        if len(encoded_data) > MAX_PAYLOAD_BYTES:
            raise InputValidationError(f"Payload exceeds maximum size of {MAX_PAYLOAD_BYTES} bytes.")

        ciphertext = self._fernet.encrypt(encoded_data)
        return ciphertext.decode("utf-8")

    def decrypt_data(self, ciphertext: str) -> str:
        """Validates and decrypts a Fernet token, verifying integrity and authenticity."""
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            raise InputValidationError("Ciphertext must be a non-empty string.")

        try:
            decrypted_bytes = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken as exc:
            # Do not reveal whether decryption failed due to tampering, wrong key, or bad format
            logger.warning("Failed decryption attempt: invalid or tampered token.")
            raise ValueError("Decryption failed: invalid token.") from exc

    def hash_password(self, password: str) -> str:
        """Hashes a password using Argon2id with an automatic cryptographically secure salt."""
        if not isinstance(password, str) or len(password) < 12:
            raise InputValidationError("Password must be a string of at least 12 characters.")
        return self._ph.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        """Verifies a plaintext password against an Argon2id hash in constant time."""
        if not isinstance(password, str) or not isinstance(password_hash, str):
            return False
        try:
            return self._ph.verify(password_hash, password)
        except VerifyMismatchError:
            return False


class UserRepository:
    """Handles database operations using parameterized queries to prevent SQL Injection."""

    def __init__(self, db_path: str, crypto: CryptoManager) -> None:
        self.db_path = db_path
        self.crypto = crypto
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    encrypted_ssn TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _validate_username(username: str) -> None:
        if not isinstance(username, str) or not USERNAME_REGEX.match(username):
            raise InputValidationError(
                "Username must be 3-32 characters and contain only letters, numbers, and underscores."
            )

    def create_user(self, username: str, password: str, sensitive_data: str) -> None:
        """Validates inputs, hashes the password, encrypts sensitive data, and inserts safely."""
        self._validate_username(username)
        password_hash = self.crypto.hash_password(password)
        encrypted_data = self.crypto.encrypt_data(sensitive_data)

        # Parameterized query (?) prevents SQL injection
        query = "INSERT INTO users (username, password_hash, encrypted_ssn) VALUES (?, ?, ?)"
        try:
            with self._get_connection() as conn:
                conn.execute(query, (username, password_hash, encrypted_data))
            logger.info("User '%s' created successfully.", username)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists.") from exc

    def authenticate_and_fetch_data(self, username: str, password: str) -> Optional[str]:
        """Authenticates the user and returns their decrypted sensitive data."""
        self._validate_username(username)

        query = "SELECT password_hash, encrypted_ssn FROM users WHERE username = ?"
        with self._get_connection() as conn:
            row = conn.execute(query, (username,)).fetchone()

        if not row:
            # Perform dummy hash verification to mitigate timing-based username enumeration
            self.crypto.verify_password(
                "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
                password,
            )
            return None

        stored_hash, encrypted_ssn = row
        if not self.crypto.verify_password(stored_hash, password):
            logger.warning("Failed login attempt for user '%s'.", username)
            return None

        return self.crypto.decrypt_data(encrypted_ssn)


# --- Example Usage ---
if __name__ == "__main__":
    # In production, set APP_ENCRYPTION_KEY in your OS/secret manager rather than generating at runtime.
    if "APP_ENCRYPTION_KEY" not in os.environ:
        os.environ["APP_ENCRYPTION_KEY"] = Fernet.generate_key().decode("utf-8")

    crypto_manager = CryptoManager()
    repo = UserRepository(db_path=":memory:", crypto=crypto_manager)

    # 1. Create a user with validated input, Argon2id password hash, and encrypted PII
    repo.create_user(
        username="alice_dev",
        password="CorrectHorseBatteryStaple99!",
        sensitive_data="123-45-6789",
    )

    # 2. Authenticate and decrypt user data
    decrypted_secret = repo.authenticate_and_fetch_data(
        username="alice_dev",
        password="CorrectHorseBatteryStaple99!",
    )
    print(f"Decrypted User Data: {decrypted_secret}")

    # 3. Verify failed authentication returns None without leaking details
    failed_attempt = repo.authenticate_and_fetch_data(
        username="alice_dev",
        password="WrongPassword123!",
    )
    print(f"Failed Auth Result: {failed_attempt}")