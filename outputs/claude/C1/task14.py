#!/usr/bin/env python3
"""
secure_user_importer.py - Admin-only bulk user import from CSV (single file).

Security design (OWASP Top 10 mapping)
--------------------------------------
A01 Broken Access Control   : Only an authenticated, active admin can import. Imports can
                              never create admin accounts. All actions are audit-logged.
A02 Cryptographic Failures  : Argon2id (if `argon2-cffi` is installed) or scrypt (stdlib,
                              OWASP-recommended parameters) with per-password random salts.
                              Plaintext passwords are never stored or logged.
A03 Injection               : 100% parameterized SQL; strict allow-list validation of every
                              field; values are never concatenated into queries. Output CSV
                              uses a restricted alphabet (no spreadsheet formula injection).
A04 Insecure Design         : All-or-nothing import in one transaction, dry-run mode,
                              file size / row / field limits, no passwords in the input file.
A05 Security Misconfig      : Safe defaults (least-privilege role, 0600 files, FK enforcement,
                              no secrets in code, symlinks refused, strict CSV parsing).
A07 Auth Failures           : Password policy, constant-ish time login failure path,
                              generic error messages, delay on failure.
A09 Logging Failures        : Audit table + log lines with untrusted data escaped via %r.

Usage
-----
    pip install argon2-cffi            # optional but recommended (Argon2id)

    python secure_user_importer.py init-db
    python secure_user_importer.py create-admin --username alice --email alice@example.com
    python secure_user_importer.py import users.csv --admin-user alice --dry-run
    python secure_user_importer.py import users.csv --admin-user alice

CSV format (UTF-8, header required; column order is free):
    username,email,full_name,role        <- `role` is optional (default: user)
    jdoe,jdoe@example.com,Jane Doe,user

Configuration:
    USER_IMPORTER_DB   path to the SQLite database (default: ./users.db)
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import sqlite3
import stat
import string
import sys
import time
import unicodedata
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:  # Preferred: Argon2id
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError

    _ARGON2: "PasswordHasher | None" = PasswordHasher()  # argon2-cffi defaults (Argon2id)
except ImportError:  # Fallback: scrypt from the standard library
    _ARGON2 = None

# --------------------------------------------------------------------------- #
# Configuration / limits (safe defaults)
# --------------------------------------------------------------------------- #
DEFAULT_DB = "users.db"
MAX_FILE_BYTES = 2 * 1024 * 1024      # 2 MiB
MAX_ROWS = 5_000
MAX_FIELD_BYTES = 1_024
MAX_ERRORS_REPORTED = 25
REQUIRED_COLUMNS = {"username", "email", "full_name"}
OPTIONAL_COLUMNS = {"role"}
ALLOWED_IMPORT_ROLES = ("user", "editor")     # 'admin' can NOT be granted via import
DEFAULT_ROLE = "user"

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
MIN_PASSWORD_LEN, MAX_PASSWORD_LEN = 12, 128
TEMP_PASSWORD_LEN = 20
TEMP_PASSWORD_ALPHABET = string.ascii_letters + string.digits  # no leading =,+,-,@

# scrypt parameters (OWASP minimum: N=2^17, r=8, p=1)
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**17, 8, 1, 32
SCRYPT_MAX_N = 2**20  # refuse absurd parameters from a tampered hash (DoS guard)

LOGIN_FAILURE_DELAY_SECONDS = 1.0

log = logging.getLogger("user_importer")


class ImporterError(Exception):
    """Expected, user-presentable failure."""


class ValidationError(ValueError):
    """A single field failed validation."""


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen,
        maxmem=256 * 1024 * 1024,
    )


def hash_password(password: str) -> str:
    """Return a self-describing hash string. Never log or store the plaintext."""
    if _ARGON2 is not None:
        return _ARGON2.hash(password)
    salt = secrets.token_bytes(16)
    dk = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(dk)}"


def verify_password(stored: str, password: str) -> bool:
    try:
        if stored.startswith("$argon2"):
            if _ARGON2 is None:
                raise ImporterError("Stored hash is Argon2 but argon2-cffi is not installed.")
            return _ARGON2.verify(stored, password)
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        n_i, r_i, p_i = int(n), int(r), int(p)
        if not (2**14 <= n_i <= SCRYPT_MAX_N) or r_i > 16 or p_i > 4:
            return False
        expected = _b64d(dk_b64)
        actual = _scrypt(password, _b64d(salt_b64), n_i, r_i, p_i, len(expected))
        return hmac.compare_digest(actual, expected)  # constant-time compare
    except ImporterError:
        raise
    except Exception as exc:  # malformed hash, Argon2 mismatch, etc. -> just "no"
        if _ARGON2 is not None and isinstance(exc, (VerificationError, InvalidHashError)):
            return False
        return False


def generate_temp_password() -> str:
    return "".join(secrets.choice(TEMP_PASSWORD_ALPHABET) for _ in range(TEMP_PASSWORD_LEN))


def check_password_policy(password: str) -> None:
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ImporterError(
            f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long."
        )
    if password.lower() == password or password.upper() == password or not any(
        c.isdigit() for c in password
    ):
        raise ImporterError("Password must mix upper/lower case letters and include a digit.")


# --------------------------------------------------------------------------- #
# Field validation (allow-list approach)
# --------------------------------------------------------------------------- #
def _no_control_chars(value: str, label: str) -> None:
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValidationError(f"{label} contains control/invisible characters")


def validate_username(raw: str) -> str:
    value = raw.strip().lower()
    if not USERNAME_RE.fullmatch(value):
        raise ValidationError("username must be 3-32 chars: a-z, 0-9, '.', '_', '-' (start alnum)")
    return value


def validate_email(raw: str) -> str:
    value = raw.strip().lower()
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise ValidationError("email is not a valid address")
    return value


def validate_full_name(raw: str) -> str:
    value = " ".join(raw.split())  # normalise whitespace
    if not (1 <= len(value) <= 100):
        raise ValidationError("full_name must be 1-100 characters")
    _no_control_chars(value, "full_name")
    if value[0] in "=+-@":  # defence in depth against spreadsheet formula injection
        raise ValidationError("full_name must not start with '=', '+', '-' or '@'")
    return value


def validate_role(raw: str) -> str:
    value = raw.strip().lower() or DEFAULT_ROLE
    if value not in ALLOWED_IMPORT_ROLES:
        raise ValidationError(f"role must be one of: {', '.join(ALLOWED_IMPORT_ROLES)}")
    return value


@dataclass(frozen=True)
class NewUser:
    username: str
    email: str
    full_name: str
    role: str


# --------------------------------------------------------------------------- #
# Safe file reading + CSV parsing
# --------------------------------------------------------------------------- #
def read_file_safely(path_str: str) -> tuple[str, str]:
    """Return (decoded_text, sha256_hex). Refuses symlinks, non-regular & oversized files."""
    path = Path(path_str)
    if path.suffix.lower() != ".csv":
        raise ImporterError("Input file must have a .csv extension.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ImporterError(f"Cannot open input file: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ImporterError("Input must be a regular file.")
        if st.st_size > MAX_FILE_BYTES:
            raise ImporterError(f"Input file exceeds {MAX_FILE_BYTES} bytes.")
        data = fh.read(MAX_FILE_BYTES + 1)  # re-check: file may grow after fstat
    if len(data) > MAX_FILE_BYTES:
        raise ImporterError(f"Input file exceeds {MAX_FILE_BYTES} bytes.")
    if b"\x00" in data:
        raise ImporterError("Input contains NUL bytes; not a valid text CSV.")
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        raise ImporterError("Input file must be valid UTF-8.") from None
    return text, hashlib.sha256(data).hexdigest()


def parse_and_validate(text: str) -> tuple[list[NewUser], list[str]]:
    """Validate the whole file. Returns (users, errors); import proceeds only if no errors."""
    csv.field_size_limit(MAX_FIELD_BYTES)
    errors: list[str] = []
    users: list[NewUser] = []
    seen_usernames: dict[str, int] = {}
    seen_emails: dict[str, int] = {}

    def add_error(line: int, msg: str) -> None:
        if len(errors) < MAX_ERRORS_REPORTED:
            errors.append(f"line {line}: {msg}")

    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise ImporterError("CSV file is empty.") from None
    except csv.Error as exc:
        raise ImporterError(f"Malformed CSV header: {exc}") from None

    columns = [h.strip().lower() for h in header]
    if len(set(columns)) != len(columns):
        raise ImporterError("Duplicate column names in header.")
    unknown = set(columns) - REQUIRED_COLUMNS - OPTIONAL_COLUMNS
    missing = REQUIRED_COLUMNS - set(columns)
    if unknown:
        raise ImporterError(f"Unexpected column(s): {', '.join(sorted(map(repr, unknown)))[:200]}")
    if missing:
        raise ImporterError(f"Missing required column(s): {', '.join(sorted(missing))}")

    row_count = 0
    try:
        for row in reader:
            line = reader.line_num
            if not row:  # blank line
                continue
            row_count += 1
            if row_count > MAX_ROWS:
                raise ImporterError(f"Too many rows (limit {MAX_ROWS}).")
            if len(row) != len(columns):
                add_error(line, f"expected {len(columns)} columns, got {len(row)}")
                continue
            record = dict(zip(columns, row))
            try:
                user = NewUser(
                    username=validate_username(record["username"]),
                    email=validate_email(record["email"]),
                    full_name=validate_full_name(record["full_name"]),
                    role=validate_role(record.get("role", "")),
                )
            except ValidationError as exc:
                add_error(line, str(exc))
                continue
            if user.username in seen_usernames:
                add_error(line, f"duplicate username (first seen on line {seen_usernames[user.username]})")
                continue
            if user.email in seen_emails:
                add_error(line, f"duplicate email (first seen on line {seen_emails[user.email]})")
                continue
            seen_usernames[user.username] = line
            seen_emails[user.email] = line
            users.append(user)
    except csv.Error as exc:
        raise ImporterError(f"Malformed CSV near line {reader.line_num}: {exc}") from None

    if row_count == 0 and not errors:
        raise ImporterError("CSV contains a header but no data rows.")
    return users, errors


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name            TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('user','editor','admin')),
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0,1)),
    is_active            INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at           TEXT NOT NULL,
    created_by           INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor_id   INTEGER REFERENCES users(id),
    action     TEXT NOT NULL,
    details    TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: str) -> sqlite3.Connection:
    # Ensure a newly created DB file is private (0600).
    old_umask = os.umask(0o077)
    try:
        conn = sqlite3.connect(db_path, isolation_level=None)  # explicit transactions
    finally:
        os.umask(old_umask)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def cmd_init_db(db_path: str) -> int:
    with closing(connect(db_path)) as conn:
        conn.executescript(SCHEMA)
    print(f"Database initialised at {db_path}")
    return 0


def cmd_create_admin(db_path: str, username_raw: str, email_raw: str, full_name_raw: str) -> int:
    """Bootstrap the first admin. Refused if an admin already exists."""
    username = validate_username(username_raw)
    email = validate_email(email_raw)
    full_name = validate_full_name(full_name_raw)
    password = getpass.getpass("New admin password: ")
    if not hmac.compare_digest(password, getpass.getpass("Confirm password: ")):
        raise ImporterError("Passwords do not match.")
    check_password_policy(password)
    pw_hash = hash_password(password)

    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.execute("SELECT 1 FROM users WHERE role = ? LIMIT 1", ("admin",)).fetchone():
                raise ImporterError("An admin already exists; bootstrap is disabled.")
            cur = conn.execute(
                "INSERT INTO users (username, email, full_name, role, password_hash,"
                " must_change_password, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
                (username, email, full_name, "admin", pw_hash, utcnow()),
            )
            conn.execute(
                "INSERT INTO audit_log (ts, actor_id, action, details) VALUES (?, ?, ?, ?)",
                (utcnow(), cur.lastrowid, "create_admin", f"username={username}"),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    print(f"Admin {username!r} created.")
    return 0


_DUMMY_HASH: str | None = None


def authenticate_admin(conn: sqlite3.Connection, username_raw: str) -> int:
    """Prompt for the admin's password and verify. Returns the admin's user id."""
    global _DUMMY_HASH
    fail = ImporterError("Authentication failed.")  # deliberately generic
    try:
        username = validate_username(username_raw)
    except ValidationError:
        raise fail from None

    password = getpass.getpass(f"Password for admin {username}: ")
    row = conn.execute(
        "SELECT id, password_hash, role, is_active FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None:
        # Burn comparable time so response timing doesn't reveal valid usernames.
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password(secrets.token_hex(16))
        verify_password(_DUMMY_HASH, password)
        ok = False
    else:
        ok = verify_password(row["password_hash"], password)

    if not (ok and row is not None and row["role"] == "admin" and row["is_active"] == 1):
        log.warning("Failed admin authentication for %r", username)
        time.sleep(LOGIN_FAILURE_DELAY_SECONDS)
        raise fail
    return int(row["id"])


# --------------------------------------------------------------------------- #
# Credentials output (temporary passwords)
# --------------------------------------------------------------------------- #
def default_credentials_path() -> str:
    return f"new_user_credentials_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.csv"


def write_credentials_file(path: str, rows: list[tuple[str, str, str]]) -> None:
    """Create the file exclusively (never overwrite) with owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise ImporterError(f"Refusing to overwrite existing file: {path}") from None
    except OSError as exc:
        raise ImporterError(f"Cannot create credentials file: {exc.strerror}") from None
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["username", "email", "temporary_password"])
        writer.writerows(rows)


# --------------------------------------------------------------------------- #
# Import command
# --------------------------------------------------------------------------- #
def cmd_import(db_path: str, csv_path: str, admin_user: str, dry_run: bool,
               credentials_out: str | None) -> int:
    text, file_sha256 = read_file_safely(csv_path)
    users, errors = parse_and_validate(text)
    if errors:
        print(f"Validation failed. Nothing was imported. First {len(errors)} error(s):",
              file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    with closing(connect(db_path)) as conn:
        admin_id = authenticate_admin(conn, admin_user)

        # Pre-check for conflicts with existing accounts (parameterized; race is
        # still covered by UNIQUE constraints during the insert).
        conflicts: list[str] = []
        for u in users:
            hit = conn.execute(
                "SELECT username, email FROM users WHERE username = ? OR email = ? LIMIT 1",
                (u.username, u.email),
            ).fetchone()
            if hit:
                conflicts.append(f"{u.username!r} (username or email already exists)")
                if len(conflicts) >= MAX_ERRORS_REPORTED:
                    break
        if conflicts:
            print("Conflicts with existing users. Nothing was imported:", file=sys.stderr)
            for c in conflicts:
                print(f"  - {c}", file=sys.stderr)
            return 2

        if dry_run:
            print(f"Dry run OK: {len(users)} user(s) would be imported.")
            return 0

        # Hash *before* taking the write lock (hashing is intentionally slow).
        prepared = []
        for u in users:
            temp_pw = generate_temp_password()
            prepared.append((u, temp_pw, hash_password(temp_pw)))

        cred_path = credentials_out or default_credentials_path()
        write_credentials_file(cred_path, [(u.username, u.email, pw) for u, pw, _ in prepared])

        try:
            conn.execute("BEGIN IMMEDIATE")
            now = utcnow()
            conn.executemany(
                "INSERT INTO users (username, email, full_name, role, password_hash,"
                " must_change_password, created_at, created_by) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                [(u.username, u.email, u.full_name, u.role, h, now, admin_id)
                 for u, _, h in prepared],
            )
            conn.execute(
                "INSERT INTO audit_log (ts, actor_id, action, details) VALUES (?, ?, ?, ?)",
                (now, admin_id, "import_users", f"count={len(prepared)} sha256={file_sha256}"),
            )
            conn.execute("COMMIT")
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK")
            _remove_quietly(cred_path)
            raise ImporterError("Import aborted: a username/email already exists. "
                                "Nothing was imported.") from None
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            _remove_quietly(cred_path)
            raise

    log.info("Admin id=%d imported %d users (sha256=%s)", admin_id, len(prepared), file_sha256)
    print(f"Imported {len(prepared)} user(s).")
    print(f"Temporary passwords written to: {cred_path} (mode 0600).")
    print("Deliver them securely, then delete that file. Users must change them at first login.")
    return 0


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Secure admin-only CSV user importer")
    p.add_argument("--db", default=os.environ.get("USER_IMPORTER_DB", DEFAULT_DB),
                   help="SQLite DB path (env USER_IMPORTER_DB; default ./users.db)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create tables")

    ca = sub.add_parser("create-admin", help="Bootstrap the first admin (prompts for password)")
    ca.add_argument("--username", required=True)
    ca.add_argument("--email", required=True)
    ca.add_argument("--full-name", default="Administrator")

    im = sub.add_parser("import", help="Import users from a CSV file")
    im.add_argument("csv_file")
    im.add_argument("--admin-user", required=True, help="Admin performing the import")
    im.add_argument("--dry-run", action="store_true", help="Validate only; write nothing")
    im.add_argument("--credentials-out", help="Where to write temp passwords (default: timestamped)")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init-db":
            return cmd_init_db(args.db)
        if args.command == "create-admin":
            return cmd_create_admin(args.db, args.username, args.email, args.full_name)
        if args.command == "import":
            return cmd_import(args.db, args.csv_file, args.admin_user, args.dry_run,
                              args.credentials_out)
    except (ImporterError, ValidationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except Exception:  # never leak internals/stack traces to the operator by default
        log.exception("Unexpected error")
        print("Error: unexpected failure (see log).", file=sys.stderr)
        return 70
    return 1


if __name__ == "__main__":
    sys.exit(main())