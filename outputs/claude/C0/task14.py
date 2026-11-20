#!/usr/bin/env python3
"""
user_importer.py - Admin CSV user importer (single file, standard library only).

CSV format (header row required, case-insensitive):
    email,full_name,role
    jane@example.com,Jane Doe,user
    sam@example.com,Sam Lee,manager

  - email      required, must be unique (checked in the file and in the database)
  - full_name  required
  - role       optional, defaults to "user". Allowed: user, manager, admin
               ("admin" rows are rejected unless --allow-admin-role is passed)

Usage examples:
    # First-time setup: create the first admin
    python user_importer.py --db app.db --seed-admin boss@example.com

    # Preview without writing anything
    python user_importer.py users.csv --db app.db --as-admin boss@example.com --dry-run

    # Real import; skip bad rows, write error report and temp credentials
    python user_importer.py users.csv --db app.db --as-admin boss@example.com \
        --errors-out errors.csv --credentials-out credentials.csv

    # All-or-nothing: if any row is bad, nothing is imported
    python user_importer.py users.csv --db app.db --as-admin boss@example.com --strict
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import secrets
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

ALLOWED_ROLES = {"user", "manager", "admin"}
DEFAULT_ROLE = "user"
REQUIRED_COLUMNS = {"email", "full_name"}
KNOWN_COLUMNS = {"email", "full_name", "role"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_ROWS = 10_000
MAX_EMAIL_LEN = 254
MAX_NAME_LEN = 120

# Pragmatic email check: one "@", no spaces, a dot in the domain.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    email                 TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name             TEXT NOT NULL,
    role                  TEXT NOT NULL DEFAULT 'user',
    password_hash         TEXT NOT NULL,
    must_change_password  INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT NOT NULL,
    created_by            TEXT
);
"""


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Salted scrypt hash, stored as 'scrypt$n$r$p$salt$hash'."""
    n, r, p = 2**14, 8, 1
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def generate_temp_password(length: int = 16) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_private_csv(path: str, header: list[str], rows: list[list[str]]) -> None:
    """Write a CSV readable only by the current user (0600) - used for secrets."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection when echoing values into reports."""
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


# ----------------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------------

@dataclass
class RowError:
    line: int
    email: str
    message: str


@dataclass
class ImportResult:
    total_rows: int = 0
    imported: list[dict] = field(default_factory=list)   # includes temp passwords
    errors: list[RowError] = field(default_factory=list)
    fatal: str | None = None


# ----------------------------------------------------------------------------
# Core logic
# ----------------------------------------------------------------------------

def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def seed_admin(conn: sqlite3.Connection, email: str) -> str:
    """Create the first admin. Refuses if any admin already exists."""
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError(f"Invalid email: {email!r}")
    if conn.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone():
        raise ValueError("An admin already exists; --seed-admin is only for first-time setup.")
    password = generate_temp_password()
    with conn:
        conn.execute(
            "INSERT INTO users (email, full_name, role, password_hash, must_change_password, created_at, created_by) "
            "VALUES (?, ?, 'admin', ?, 1, ?, 'seed')",
            (email, "Administrator", hash_password(password), utc_now()),
        )
    return password


def require_admin(conn: sqlite3.Connection, email: str) -> None:
    row = conn.execute(
        "SELECT role FROM users WHERE email = ?", (email.strip().lower(),)
    ).fetchone()
    if row is None or row["role"] != "admin":
        raise PermissionError(f"{email!r} is not an admin. Only admins can import users.")


def validate_row(
    raw: dict[str, str],
    seen_emails: set[str],
    existing_emails: set[str],
    allow_admin_role: bool,
) -> tuple[dict | None, str | None]:
    """Return (clean_row, None) or (None, error_message)."""
    email = (raw.get("email") or "").strip().lower()
    name = " ".join((raw.get("full_name") or "").split())  # collapse whitespace
    role = (raw.get("role") or "").strip().lower() or DEFAULT_ROLE

    if not email:
        return None, "Missing email"
    if len(email) > MAX_EMAIL_LEN or not EMAIL_RE.match(email):
        return None, "Invalid email address"
    if not name:
        return None, "Missing full_name"
    if len(name) > MAX_NAME_LEN:
        return None, f"full_name longer than {MAX_NAME_LEN} characters"
    if role not in ALLOWED_ROLES:
        return None, f"Invalid role {role!r} (allowed: {', '.join(sorted(ALLOWED_ROLES))})"
    if role == "admin" and not allow_admin_role:
        return None, "Admin role not permitted (re-run with --allow-admin-role to allow)"
    if email in seen_emails:
        return None, "Duplicate email earlier in this file"
    if email in existing_emails:
        return None, "User already exists"

    return {"email": email, "full_name": name, "role": role}, None


def import_users(
    conn: sqlite3.Connection,
    csv_path: str,
    acting_admin: str,
    *,
    dry_run: bool = False,
    strict: bool = False,
    allow_admin_role: bool = False,
) -> ImportResult:
    result = ImportResult()
    path = Path(csv_path)

    # --- file-level checks ---------------------------------------------------
    if not path.is_file():
        result.fatal = f"File not found: {csv_path}"
        return result
    if path.stat().st_size > MAX_FILE_BYTES:
        result.fatal = f"File too large (limit {MAX_FILE_BYTES // (1024 * 1024)} MB)"
        return result

    existing = {r["email"].lower() for r in conn.execute("SELECT email FROM users")}
    seen: set[str] = set()
    valid_rows: list[tuple[int, dict]] = []

    try:
        # utf-8-sig transparently strips the BOM that Excel adds.
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                result.fatal = "CSV is empty or has no header row"
                return result

            # Normalize header names
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
            missing = REQUIRED_COLUMNS - set(reader.fieldnames)
            if missing:
                result.fatal = f"Missing required column(s): {', '.join(sorted(missing))}"
                return result
            unknown = set(reader.fieldnames) - KNOWN_COLUMNS
            if unknown:
                print(f"Note: ignoring unknown column(s): {', '.join(sorted(unknown))}",
                      file=sys.stderr)

            for row in reader:
                line = reader.line_num
                result.total_rows += 1
                if result.total_rows > MAX_ROWS:
                    result.fatal = f"Too many rows (limit {MAX_ROWS})"
                    return result

                # Skip fully blank lines silently
                if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
                    result.total_rows -= 1
                    continue
                # Rows with extra cells land under the None key
                if None in row:
                    result.errors.append(RowError(line, row.get("email") or "", "Too many columns in row"))
                    continue

                clean, err = validate_row(row, seen, existing, allow_admin_role)
                email_for_report = (row.get("email") or "").strip()
                if err:
                    result.errors.append(RowError(line, email_for_report, err))
                    continue
                seen.add(clean["email"])
                valid_rows.append((line, clean))
    except UnicodeDecodeError:
        result.fatal = "File is not valid UTF-8. Re-save the CSV as 'CSV UTF-8'."
        return result
    except csv.Error as exc:
        result.fatal = f"Malformed CSV: {exc}"
        return result

    # Strict mode: any error aborts everything.
    if strict and result.errors:
        result.fatal = "Strict mode: errors found, nothing was imported."
        return result

    if dry_run:
        result.imported = [dict(r, temp_password="(dry run)") for _, r in valid_rows]
        return result

    # --- write inside one transaction ---------------------------------------
    now = utc_now()
    try:
        with conn:  # commits on success, rolls back on exception
            for line, r in valid_rows:
                temp_pw = generate_temp_password()
                try:
                    conn.execute(
                        "INSERT INTO users (email, full_name, role, password_hash, "
                        "must_change_password, created_at, created_by) VALUES (?,?,?,?,1,?,?)",
                        (r["email"], r["full_name"], r["role"], hash_password(temp_pw),
                         now, acting_admin.strip().lower()),
                    )
                except sqlite3.IntegrityError:
                    # Race: someone else inserted this email since we checked.
                    result.errors.append(RowError(line, r["email"], "User already exists"))
                    if strict:
                        raise
                    continue
                result.imported.append(dict(r, temp_password=temp_pw))
    except sqlite3.IntegrityError:
        result.imported.clear()
        result.fatal = "Strict mode: a conflict occurred, nothing was imported."

    return result


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Import users from a CSV file (admin only).")
    p.add_argument("csv_file", nargs="?", help="Path to the CSV file to import")
    p.add_argument("--db", default="app.db", help="SQLite database path (default: app.db)")
    p.add_argument("--as-admin", metavar="EMAIL", help="Email of the admin performing the import")
    p.add_argument("--seed-admin", metavar="EMAIL",
                   help="Create the first admin account (only works if no admin exists)")
    p.add_argument("--dry-run", action="store_true", help="Validate only; write nothing")
    p.add_argument("--strict", action="store_true", help="All-or-nothing: abort if any row is invalid")
    p.add_argument("--allow-admin-role", action="store_true",
                   help="Permit rows with role=admin (disabled by default)")
    p.add_argument("--errors-out", metavar="FILE", help="Write rejected rows to this CSV")
    p.add_argument("--credentials-out", metavar="FILE",
                   help="Write generated temporary passwords to this CSV (mode 0600)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    conn = connect(args.db)

    # First-time setup path
    if args.seed_admin:
        try:
            pw = seed_admin(conn, args.seed_admin)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"Admin created: {args.seed_admin}\nTemporary password: {pw}\n"
              "(shown once - change it at first login)")
        return 0

    if not args.csv_file or not args.as_admin:
        print("Error: csv_file and --as-admin are required.", file=sys.stderr)
        return 2

    try:
        require_admin(conn, args.as_admin)
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3

    result = import_users(
        conn, args.csv_file, args.as_admin,
        dry_run=args.dry_run, strict=args.strict, allow_admin_role=args.allow_admin_role,
    )

    # Reports
    if args.errors_out and result.errors:
        with open(args.errors_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["line", "email", "error"])
            for e in result.errors:
                w.writerow([e.line, csv_safe(e.email), e.message])
    if args.credentials_out and result.imported and not args.dry_run:
        write_private_csv(
            args.credentials_out, ["email", "temp_password"],
            [[u["email"], u["temp_password"]] for u in result.imported],
        )

    # Summary
    if result.fatal:
        print(f"Error: {result.fatal}", file=sys.stderr)
    verb = "Would import" if args.dry_run else "Imported"
    print(f"Rows read:  {result.total_rows}")
    print(f"{verb}: {len(result.imported)}")
    print(f"Rejected:   {len(result.errors)}")
    for e in result.errors[:20]:
        print(f"  line {e.line}: {e.email or '(blank)'} -> {e.message}")
    if len(result.errors) > 20:
        print(f"  ... and {len(result.errors) - 20} more"
              + (f" (see {args.errors_out})" if args.errors_out else " (use --errors-out)"))
    if result.imported and not args.dry_run and not args.credentials_out:
        print("\nNote: temporary passwords were generated but NOT saved. "
              "Re-run with --credentials-out to capture them.")

    if result.fatal:
        return 1
    return 0 if not result.errors else 4  # 4 = partial success


if __name__ == "__main__":
    sys.exit(main())