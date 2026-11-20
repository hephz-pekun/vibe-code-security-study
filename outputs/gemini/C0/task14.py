import argparse
import csv
import hashlib
import os
import re
import secrets
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Tuple

# Configuration
REQUIRED_HEADERS = {"username", "email", "role", "password"}
ALLOWED_ROLES = {"admin", "editor", "viewer", "user"}
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


@dataclass
class UserRecord:
    username: str
    email: str
    role: str
    password_hash: str


def init_db(db_path: str) -> sqlite3.Connection:
    """Initializes the SQLite database and creates the users table if missing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def hash_password(password: str) -> str:
    """Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return f"{salt}${pwd_hash}"


def get_existing_users(conn: sqlite3.Connection) -> Tuple[Set[str], Set[str]]:
    """Fetches existing usernames and emails to prevent duplicate imports."""
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users")
    rows = cursor.fetchall()
    existing_usernames = {row[0].lower() for row in rows}
    existing_emails = {row[1].lower() for row in rows}
    return existing_usernames, existing_emails


def validate_and_parse_csv(
    csv_path: Path, existing_usernames: Set[str], existing_emails: Set[str]
) -> Tuple[List[UserRecord], List[str]]:
    """
    Reads the CSV, validates headers and row data, and returns valid records
    alongside a list of row-level error messages.
    """
    valid_users: List[UserRecord] = []
    errors: List[str] = []

    seen_usernames = set(existing_usernames)
    seen_emails = set(existing_emails)

    with csv_path.open(mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing a header row.")

        # Normalize headers to lowercase and strip whitespace
        normalized_headers = {h.strip().lower() for h in reader.fieldnames if h}
        missing_headers = REQUIRED_HEADERS - normalized_headers
        if missing_headers:
            raise ValueError(
                f"Missing required columns: {', '.join(sorted(missing_headers))}"
            )

        for row_num, raw_row in enumerate(reader, start=2):
            # Normalize keys and strip values
            row = {
                k.strip().lower(): (v.strip() if v is not None else "")
                for k, v in raw_row.items()
                if k is not None
            }

            username = row.get("username", "")
            email = row.get("email", "").lower()
            role = row.get("role", "").lower()
            password = row.get("password", "")

            # 1. Presence check
            if not all([username, email, role, password]):
                errors.append(f"Row {row_num}: Missing one or more required fields.")
                continue

            # 2. Email validation
            if not EMAIL_REGEX.match(email):
                errors.append(f"Row {row_num}: Invalid email format '{email}'.")
                continue

            # 3. Role validation
            if role not in ALLOWED_ROLES:
                errors.append(
                    f"Row {row_num}: Invalid role '{role}'. Allowed: {', '.join(sorted(ALLOWED_ROLES))}."
                )
                continue

            # 4. Password length check
            if len(password) < 8:
                errors.append(
                    f"Row {row_num}: Password for '{username}' must be at least 8 characters."
                )
                continue

            # 5. Duplicate check (against DB and earlier rows in the same CSV)
            if username.lower() in seen_usernames:
                errors.append(
                    f"Row {row_num}: Duplicate username '{username}' already exists."
                )
                continue

            if email in seen_emails:
                errors.append(
                    f"Row {row_num}: Duplicate email '{email}' already exists."
                )
                continue

            seen_usernames.add(username.lower())
            seen_emails.add(email)

            valid_users.append(
                UserRecord(
                    username=username,
                    email=email,
                    role=role,
                    password_hash=hash_password(password),
                )
            )

    return valid_users, errors


def insert_users(conn: sqlite3.Connection, users: List[UserRecord]) -> int:
    """Inserts validated users into the database within a single transaction."""
    if not users:
        return 0

    cursor = conn.cursor()
    try:
        cursor.executemany(
            """
            INSERT INTO users (username, email, role, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            [(u.username, u.email, u.role, u.password_hash) for u in users],
        )
        conn.commit()
        return cursor.rowcount
    except sqlite3.Error as e:
        conn.rollback()
        raise RuntimeError(f"Database transaction failed: {e}") from e


def create_sample_csv(sample_path: Path) -> None:
    """Generates a sample CSV file for testing."""
    rows = [
        ["username", "email", "role", "password"],
        ["jdoe", "jane.doe@example.com", "admin", "Str0ngPass!"],
        ["asmith", "alex.smith@example.com", "editor", "SecurePass2026"],
        ["bwayne", "bruce@wayne.com", "viewer", "BatCave99"],
    ]
    with sample_path.open(mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"Created sample CSV at: {sample_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Admin CLI tool to import users from a CSV file into SQLite."
    )
    parser.add_argument("csv_file", nargs="?", help="Path to the input CSV file.")
    parser.add_argument(
        "--db",
        default="users.db",
        help="Path to the SQLite database file (default: users.db).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the CSV without writing changes to the database.",
    )
    parser.add_argument(
        "--generate-sample",
        metavar="PATH",
        help="Generate a template CSV file at the specified path and exit.",
    )

    args = parser.parse_args()

    if args.generate_sample:
        create_sample_csv(Path(args.generate_sample))
        sys.exit(0)

    if not args.csv_file:
        parser.error("Please provide a csv_file path or use --generate-sample.")

    csv_path = Path(args.csv_file)
    if not csv_path.is_file():
        print(f"Error: File '{csv_path}' not found.", file=sys.stderr)
        sys.exit(1)

    conn = init_db(args.db)

    try:
        existing_usernames, existing_emails = get_existing_users(conn)
        valid_users, errors = validate_and_parse_csv(
            csv_path, existing_usernames, existing_emails
        )

        print(f"--- Import Summary for '{csv_path.name}' ---")
        print(f"Valid rows ready : {len(valid_users)}")
        print(f"Skipped / Errors : {len(errors)}")

        if errors:
            print("\nValidation Issues:")
            for err in errors:
                print(f"  - {err}")

        if args.dry_run:
            print("\n[Dry Run] No changes were written to the database.")
        elif valid_users:
            inserted_count = insert_users(conn, valid_users)
            print(f"\nSuccess: {inserted_count} user(s) imported into '{args.db}'.")
        else:
            print("\nNo valid users to import.")

    except ValueError as e:
        print(f"CSV Format Error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"Import Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()