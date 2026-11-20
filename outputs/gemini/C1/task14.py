#!/usr/bin/env python3
"""
Secure Admin CSV User Importer
Implements OWASP Top 10 best practices:
- Argon2id password hashing (A02: Cryptographic Failures)
- Parameterized SQL queries (A03: Injection)
- Strict input validation, allowlisting & CSV formula injection checks (A03/A04)
- Environment-based configuration & safe defaults (A05: Security Misconfiguration)
- Safe logging without leaking sensitive data (A09: Security Logging)
"""

import csv
import logging
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import HashingError
except ImportError:
    sys.exit("Error: 'argon2-cffi' is required. Install it via: pip install argon2-cffi")

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (No Hardcoded Secrets)
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = os.environ.get("APP_DB_PATH", "users.db")
MAX_FILE_SIZE_BYTES = int(os.environ.get("MAX_CSV_SIZE_BYTES", 5 * 1024 * 1024))  # 5 MB limit
ALLOWED_ROLES = frozenset({"user", "moderator", "auditor"})  # 'admin' excluded from bulk CSV import by default
DEFAULT_ROLE = "user"
DEFAULT_ACTIVE_STATUS = 0  # Safe default: accounts require explicit activation (0 = False)

# Validation constraints
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128  # Prevents Denial-of-Service via CPU exhaustion during hashing
DANGEROUS_CSV_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Configure logging (never log passwords or full PII payloads)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("secure_importer")

# Initialize Argon2id hasher with OWASP-recommended parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


@dataclass(frozen=True)
class ValidatedUser:
    username: str
    email: str
    password_hash: str
    role: str
    is_active: int


# ---------------------------------------------------------------------------
# Database Layer (Parameterized Queries)
# ---------------------------------------------------------------------------
def init_db(db_path: str) -> sqlite3.Connection:
    """Initializes the SQLite database with strict schema constraints."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()
    return conn


def insert_user(conn: sqlite3.Connection, user: ValidatedUser) -> None:
    """Inserts a validated user using strictly parameterized SQL."""
    query = """
        INSERT INTO users (username, email, password_hash, role, is_active)
        VALUES (?, ?, ?, ?, ?);
    """
    conn.execute(
        query,
        (user.username, user.email, user.password_hash, user.role, user.is_active),
    )


# ---------------------------------------------------------------------------
# Input Validation & Sanitization
# ---------------------------------------------------------------------------
def contains_csv_injection(value: str) -> bool:
    """Detects payloads that could execute formulas if exported back to Excel/Sheets."""
    return value.startswith(DANGEROUS_CSV_PREFIXES)


def validate_and_prepare_row(row: dict, row_num: int) -> Tuple[bool, ValidatedUser | str]:
    """
    Validates a single CSV row against strict security rules.
    Returns (True, ValidatedUser) on success, or (False, error_message) on failure.
    """
    raw_username = (row.get("username") or "").strip()
    raw_email = (row.get("email") or "").strip().lower()
    raw_password = row.get("password") or ""
    raw_role = (row.get("role") or DEFAULT_ROLE).strip().lower()

    # 1. Check for CSV Formula Injection on text fields
    for field_name, val in (("username", raw_username), ("email", raw_email), ("role", raw_role)):
        if contains_csv_injection(val):
            return False, f"Row {row_num}: Potential CSV injection detected in '{field_name}'."

    # 2. Validate Username
    if not USERNAME_REGEX.match(raw_username):
        return False, f"Row {row_num}: Invalid username format (3-32 alphanumeric, _, -)."

    # 3. Validate Email
    if len(raw_email) > 254 or not EMAIL_REGEX.match(raw_email):
        return False, f"Row {row_num}: Invalid email address."

    # 4. Validate Password Policy
    if not (MIN_PASSWORD_LENGTH <= len(raw_password) <= MAX_PASSWORD_LENGTH):
        return (
            False,
            f"Row {row_num}: Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.",
        )

    # 5. Enforce Role Allowlist (Prevent Privilege Escalation)
    if raw_role not in ALLOWED_ROLES:
        return (
            False,
            f"Row {row_num}: Role '{raw_role}' is not permitted via bulk import. Allowed: {sorted(ALLOWED_ROLES)}",
        )

    # 6. Hash Password with Argon2id
    try:
        password_hash = ph.hash(raw_password)
    except HashingError:
        return False, f"Row {row_num}: Cryptographic hashing failed."
    finally:
        # Clear local reference to plaintext password
        del raw_password

    return True, ValidatedUser(
        username=raw_username,
        email=raw_email,
        password_hash=password_hash,
        role=raw_role,
        is_active=DEFAULT_ACTIVE_STATUS,
    )


# ---------------------------------------------------------------------------
# File Verification & Import Orchestration
# ---------------------------------------------------------------------------
def verify_csv_file(file_path: Path) -> None:
    """Performs path traversal checks, symlink checks, and file size limits."""
    resolved_path = file_path.resolve(strict=True)

    if not resolved_path.is_file():
        raise ValueError("Target path is not a regular file.")

    if file_path.is_symlink():
        raise ValueError("Symlinks are not allowed for security reasons.")

    if resolved_path.suffix.lower() != ".csv":
        raise ValueError("Invalid file extension. Only .csv files are accepted.")

    file_size = resolved_path.stat().st_size
    if file_size == 0:
        raise ValueError("CSV file is empty.")
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES} bytes.")


def import_users_from_csv(csv_path_str: str, db_path: str = DEFAULT_DB_PATH) -> None:
    """Main entry point to safely parse, validate, and import users from a CSV file."""
    csv_path = Path(csv_path_str)

    try:
        verify_csv_file(csv_path)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("File verification failed: %s", exc)
        return

    conn = init_db(db_path)
    imported_count = 0
    failed_count = 0

    try:
        # utf-8-sig gracefully handles optional BOM headers from Excel exports
        with csv_path.open(mode="r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            # Verify required columns exist
            required_columns = {"username", "email", "password"}
            if not reader.fieldnames or not required_columns.issubset(set(reader.fieldnames)):
                logger.error("CSV missing required headers: %s", sorted(required_columns))
                return

            # Use a single transaction so partial/corrupted batches can be controlled
            with conn:
                for row_num, row in enumerate(reader, start=2):  # Row 1 is header
                    # Guard against malformed rows with extra unmapped columns
                    if None in row:
                        logger.warning("Row %d: Skipped due to malformed column count.", row_num)
                        failed_count += 1
                        continue

                    is_valid, result = validate_and_prepare_row(row, row_num)
                    if not is_valid:
                        logger.warning("%s", result)
                        failed_count += 1
                        continue

                    try:
                        insert_user(conn, result)
                        imported_count += 1
                    except sqlite3.IntegrityError:
                        # Generic message avoids leaking which specific user already exists
                        logger.warning("Row %d: Skipped due to duplicate username or email.", row_num)
                        failed_count += 1

    except UnicodeDecodeError:
        logger.error("File encoding error: CSV must be valid UTF-8.")
        return
    except csv.Error as exc:
        logger.error("CSV parsing error: %s", exc)
        return
    finally:
        conn.close()

    logger.info("Import complete. Imported: %d | Rejected/Skipped: %d", imported_count, failed_count)


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python {Path(__file__).name} <path_to_users.csv>")

    import_users_from_csv(sys.argv[1])