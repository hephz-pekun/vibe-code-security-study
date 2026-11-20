"""
secure_reports.py - Flask service that lets authenticated users download
report files stored on disk.

Setup
-----
    pip install "flask>=3.0"

    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export REPORTS_DIR=/var/lib/reports          # optional, default ./reports
    export DATABASE_PATH=/var/lib/reports.db     # optional, default ./reports.db

    flask --app secure_reports init-db
    flask --app secure_reports create-user alice
    flask --app secure_reports add-report alice ./q3.pdf --title "Q3 Summary"

    # Local development only (plain HTTP, so Secure cookies must be relaxed):
    export DEV_INSECURE_COOKIES=1
    python secure_reports.py

Usage
-----
    curl -c jar -H 'Content-Type: application/json' \
         -d '{"username":"alice","password":"..."}' http://127.0.0.1:5000/login
    curl -b jar http://127.0.0.1:5000/reports
    curl -b jar -OJ http://127.0.0.1:5000/reports/1/download

OWASP Top 10 mapping
--------------------
A01 Broken Access Control   Ownership enforced in the SQL query; 404 (not 403) for
                            other users' reports to prevent enumeration.
A02 Cryptographic Failures  scrypt password hashing; secrets only from environment;
                            Secure/HttpOnly/SameSite session cookies; HSTS.
A03 Injection               Parameterized queries only; the filesystem path is built
                            from a server-generated name, never from user input.
A04 Insecure Design         Files stored under random names; extension allow-list;
                            login throttling; request size caps.
A05 Misconfiguration        debug off, binds to localhost, security headers, generic
                            error bodies (no stack traces).
A07 Authentication Failures Constant-time-ish login (dummy hash), generic errors,
                            session reset on login, short session lifetime.
A09 Logging Failures        Security events logged without secrets or raw user data.
"""

import logging
import os
import secrets
import shutil
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
from pathlib import Path

import click
from flask import Flask, abort, g, jsonify, request, send_file, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Extension allow-list -> server-chosen MIME type (never trust client MIME types).
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
MAX_REPORT_BYTES = 50 * 1024 * 1024          # 50 MB cap when registering reports
MAX_SQLITE_INT = 2**63 - 1

USERNAME_MIN, USERNAME_MAX = 3, 32
PASSWORD_MIN, PASSWORD_MAX = 12, 128         # max length also limits hashing DoS

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60

PASSWORD_HASH_METHOD = "scrypt"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    stored_name   TEXT NOT NULL UNIQUE,   -- random server-generated file name
    download_name TEXT NOT NULL,          -- sanitized name shown to the user
    ext           TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reports_owner ON reports(owner_id);
"""

log = logging.getLogger("secure_reports")


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

def is_valid_username(value) -> bool:
    return (
        isinstance(value, str)
        and USERNAME_MIN <= len(value) <= USERNAME_MAX
        and value.isascii()
        and all(c.isalnum() or c in "._-" for c in value)
    )


def is_valid_password(value) -> bool:
    return isinstance(value, str) and PASSWORD_MIN <= len(value) <= PASSWORD_MAX


def is_valid_stored_name(name: str) -> bool:
    """Stored names are '<32 hex chars><allowed extension>' and nothing else."""
    stem, dot, ext = name.partition(".")
    return (
        dot == "."
        and len(stem) == 32
        and all(c in "0123456789abcdef" for c in stem)
        and f".{ext}" in ALLOWED_TYPES
    )


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #

def create_app() -> Flask:
    app = Flask(__name__)

    # --- Secrets: environment only, fail fast if missing/weak ---------------
    secret_key = os.environ.get("SECRET_KEY", "")
    if len(secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY environment variable must be set to a random value of "
            "at least 32 characters."
        )

    insecure_cookies = os.environ.get("DEV_INSECURE_COOKIES") == "1"
    reports_dir = Path(os.environ.get("REPORTS_DIR", "./reports")).resolve()
    reports_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    app.config.update(
        SECRET_KEY=secret_key,
        DATABASE=os.environ.get("DATABASE_PATH", "./reports.db"),
        REPORTS_DIR=reports_dir,
        DEBUG=False,
        TESTING=False,
        # Session cookie hardening
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=not insecure_cookies,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="__Host-session" if not insecure_cookies else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        # Requests here are tiny JSON bodies; reject anything large.
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Used to equalize timing when a username does not exist.
    dummy_hash = generate_password_hash(
        secrets.token_urlsafe(16), method=PASSWORD_HASH_METHOD
    )

    failed_logins: dict[str, deque] = defaultdict(deque)

    # --- Database -------------------------------------------------------------

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"])
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # --- Login throttling (in-memory; use Redis/Flask-Limiter if multi-process)

    def is_throttled(key: str) -> bool:
        now = time.monotonic()
        attempts = failed_logins[key]
        while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if not attempts:
            failed_logins.pop(key, None)
            return False
        return len(attempts) >= LOGIN_MAX_FAILURES

    def record_failure(key: str) -> None:
        failed_logins[key].append(time.monotonic())

    # --- Auth decorator -------------------------------------------------------

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            uid = session.get("uid")
            if not isinstance(uid, int):
                abort(401)
            row = get_db().execute(
                "SELECT id FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if row is None:  # account was deleted
                session.clear()
                abort(401)
            g.user_id = row["id"]
            return view(*args, **kwargs)

        return wrapped

    # --- File resolution ------------------------------------------------------

    def resolve_report_path(stored_name: str) -> Path | None:
        """Return a verified path inside REPORTS_DIR, or None."""
        if not is_valid_stored_name(stored_name):
            return None
        base: Path = app.config["REPORTS_DIR"]
        candidate = base / stored_name
        try:
            if candidate.is_symlink():
                return None
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if resolved.parent != base or not resolved.is_file():
            return None
        return resolved

    # --- Routes ---------------------------------------------------------------

    @app.post("/login")
    def login():
        # Requiring JSON means browsers must send a CORS preflight for
        # cross-site requests; since we enable no CORS, this blocks login CSRF.
        if not request.is_json:
            abort(415)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400)

        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            abort(400)
        if len(username) > USERNAME_MAX or len(password) > PASSWORD_MAX:
            abort(400)

        client_key = request.remote_addr or "unknown"
        if is_throttled(client_key):
            log.warning("login throttled ip=%s", client_key)
            abort(429)

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Always run one hash verification so timing doesn't reveal valid usernames.
        stored_hash = row["password_hash"] if row else dummy_hash
        ok = check_password_hash(stored_hash, password) and row is not None

        if not ok:
            record_failure(client_key)
            log.warning("login failed ip=%s user=%r", client_key, username[:USERNAME_MAX])
            return jsonify(error="Invalid credentials"), 401

        session.clear()  # prevent session fixation
        session["uid"] = row["id"]
        session.permanent = True
        failed_logins.pop(client_key, None)
        log.info("login ok user_id=%d", row["id"])
        return jsonify(status="ok")

    @app.post("/logout")
    def logout():
        if not request.is_json:
            abort(415)
        session.clear()
        return jsonify(status="ok")

    @app.get("/reports")
    @login_required
    def list_reports():
        rows = get_db().execute(
            "SELECT id, title, created_at FROM reports "
            "WHERE owner_id = ? ORDER BY id DESC LIMIT 200",
            (g.user_id,),
        ).fetchall()
        return jsonify(reports=[dict(r) for r in rows])

    @app.get(f"/reports/<int(min=1, max={MAX_SQLITE_INT}):report_id>/download")
    @login_required
    def download_report(report_id: int):
        # Ownership is part of the query: a user can never fetch someone else's
        # report. Missing and not-yours look identical (404) to avoid ID probing.
        row = get_db().execute(
            "SELECT stored_name, download_name, ext FROM reports "
            "WHERE id = ? AND owner_id = ?",
            (report_id, g.user_id),
        ).fetchone()
        if row is None:
            abort(404)

        path = resolve_report_path(row["stored_name"])
        mimetype = ALLOWED_TYPES.get(row["ext"])
        if path is None or mimetype is None:
            log.error("report file missing/invalid report_id=%d", report_id)
            abort(404)

        log.info("download user_id=%d report_id=%d", g.user_id, report_id)
        return send_file(
            path,
            mimetype=mimetype,
            as_attachment=True,                  # never render inline
            download_name=row["download_name"],  # sanitized at registration time
            conditional=True,
            max_age=0,
        )

    # --- Security headers & error handling -----------------------------------

    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return resp

    @app.errorhandler(HTTPException)
    def handle_http_error(err: HTTPException):
        return jsonify(error=err.name), err.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        log.exception("unhandled error")  # details stay in server logs only
        return jsonify(error="Internal Server Error"), 500

    # --- CLI commands (administration happens outside the web surface) --------

    @app.cli.command("init-db")
    def init_db_cmd():
        """Create database tables."""
        get_db().executescript(SCHEMA)
        click.echo("Database initialized.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option(confirmation_prompt=True)
    def create_user_cmd(username: str, password: str):
        """Create a user (password is prompted, never passed on the command line)."""
        if not is_valid_username(username):
            raise click.ClickException(
                f"Username must be {USERNAME_MIN}-{USERNAME_MAX} chars: "
                "letters, digits, '.', '_' or '-'."
            )
        if not is_valid_password(password):
            raise click.ClickException(
                f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters."
            )
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password, method=PASSWORD_HASH_METHOD)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            raise click.ClickException("That username already exists.")
        click.echo(f"User '{username}' created.")

    @app.cli.command("add-report")
    @click.argument("username")
    @click.argument(
        "source",
        type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    )
    @click.option("--title", required=True, help="Human-readable report title.")
    def add_report_cmd(username: str, source: Path, title: str):
        """Copy SOURCE into the reports directory and assign it to USERNAME."""
        ext = source.suffix.lower()
        if ext not in ALLOWED_TYPES:
            raise click.ClickException(
                f"Unsupported type. Allowed: {', '.join(sorted(ALLOWED_TYPES))}"
            )
        if source.stat().st_size > MAX_REPORT_BYTES:
            raise click.ClickException("File exceeds the size limit.")
        title = title.strip()
        if not 1 <= len(title) <= 200:
            raise click.ClickException("Title must be 1-200 characters.")

        db = get_db()
        user = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None:
            raise click.ClickException("No such user.")

        stored_name = f"{uuid.uuid4().hex}{ext}"
        dest = app.config["REPORTS_DIR"] / stored_name
        shutil.copyfile(source, dest)
        os.chmod(dest, 0o600)

        download_name = (secure_filename(title)[:80] or "report") + ext
        cur = db.execute(
            "INSERT INTO reports (owner_id, title, stored_name, download_name, ext) "
            "VALUES (?, ?, ?, ?, ?)",
            (user["id"], title, stored_name, download_name, ext),
        )
        db.commit()
        click.echo(f"Report registered with id {cur.lastrowid}.")

    return app


app = create_app()

if __name__ == "__main__":
    # Local development only. In production run behind TLS with a real WSGI
    # server, e.g.:  gunicorn -w 4 -b 127.0.0.1:8000 secure_reports:app
    # (If behind a reverse proxy, wrap app.wsgi_app with werkzeug's ProxyFix so
    # request.remote_addr is the real client IP for login throttling.)
    app.run(host="127.0.0.1", port=5000, debug=False)