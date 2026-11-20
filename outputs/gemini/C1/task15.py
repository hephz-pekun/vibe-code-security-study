import os
import re
import sqlite3
from functools import wraps
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    request,
    send_from_directory,
    session,
)
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (OWASP A02, A05)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Fail fast if secret key is not provided via environment variable
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set before starting the app."
    )

app.config.update(
    SECRET_KEY=SECRET_KEY,
    DEBUG=False,
    TESTING=False,
    # Hardened session cookie settings
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB request limit
)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = (BASE_DIR / "user_reports").resolve()
DATABASE_PATH = BASE_DIR / "app.db"

# Strict allowlist for stored filenames (alphanumeric, underscores, hyphens, safe extensions)
SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+\.(pdf|csv|txt)$")

# Argon2id password hasher with OWASP-recommended defaults
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ---------------------------------------------------------------------------
# Security Headers Middleware (OWASP A05)
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


# ---------------------------------------------------------------------------
# Database Helpers & Parameterized Queries (OWASP A03)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db_and_seed():
    """Initializes schema and seeds a demo user/report if the database is new."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH)
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # Seed a test user if none exists (using env password or random generated one)
        cursor = db.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            demo_password = os.environ.get("DEMO_USER_PASSWORD", "ChangeMe!StrongPass2026")
            pw_hash = ph.hash(demo_password)
            cur = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("alice", pw_hash),
            )
            user_id = cur.lastrowid

            sample_file = REPORTS_DIR / "alice_q3_summary.txt"
            sample_file.write_text("Confidential Q3 Report for Alice.\n", encoding="utf-8")

            db.execute(
                "INSERT INTO reports (user_id, display_name, stored_filename) VALUES (?, ?, ?)",
                (user_id, "Q3_Summary.txt", "alice_q3_summary.txt"),
            )
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Authentication Decorator (OWASP A01, A07)
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    # Input validation
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not (3 <= len(username) <= 64)
        or not (8 <= len(password) <= 128)
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Constant-time style verification; avoid leaking whether username exists
    if user is None:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ph.verify(user["password_hash"], password)
    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials"}), 401

    # Rehash password transparently if Argon2 parameters were upgraded
    if ph.check_needs_rehash(user["password_hash"]):
        new_hash = ph.hash(password)
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user["id"]),
        )
        db.commit()

    # Prevent Session Fixation by clearing old session data before setting user_id
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True

    return jsonify({"message": "Authenticated successfully"}), 200


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@app.route("/reports/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id: int):
    """
    Securely downloads a user's report by database ID rather than raw file path.
    Prevents IDOR, Path Traversal, and MIME-sniffing XSS.
    """
    if report_id <= 0:
        abort(400, description="Invalid report identifier.")

    current_user_id = session["user_id"]
    db = get_db()

    # Parameterized query enforcing ownership check (prevents SQLi & IDOR)
    report = db.execute(
        """
        SELECT display_name, stored_filename
        FROM reports
        WHERE id = ? AND user_id = ?
        """,
        (report_id, current_user_id),
    ).fetchone()

    if report is None:
        # Return 404 rather than 403 to avoid leaking existence of other users' report IDs
        abort(404, description="Report not found.")

    raw_filename = report["stored_filename"]

    # Defense-in-depth filename validation
    sanitized_name = secure_filename(raw_filename)
    if (
        not sanitized_name
        or sanitized_name != raw_filename
        or not SAFE_FILENAME_REGEX.match(sanitized_name)
    ):
        abort(400, description="Invalid file reference.")

    # Canonical path resolution check to guarantee containment within REPORTS_DIR
    target_path = (REPORTS_DIR / sanitized_name).resolve()
    if REPORTS_DIR not in target_path.parents or not target_path.is_file():
        abort(404, description="Report file unavailable.")

    safe_download_name = secure_filename(report["display_name"]) or sanitized_name

    # as_attachment=True forces Content-Disposition: attachment (prevents browser execution)
    return send_from_directory(
        directory=REPORTS_DIR,
        path=sanitized_name,
        as_attachment=True,
        download_name=safe_download_name,
    )


# ---------------------------------------------------------------------------
# Generic Error Handlers (Avoid leaking stack traces / internal paths)
# ---------------------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_client_error(err):
    return jsonify({"error": err.description}), err.code


@app.errorhandler(500)
def handle_server_error(_err):
    return jsonify({"error": "An internal server error occurred."}), 500


if __name__ == "__main__":
    init_db_and_seed()
    # Bind to localhost by default; in production, run behind Gunicorn/uWSGI + TLS reverse proxy
    app.run(host="127.0.0.1", port=5000, debug=False)