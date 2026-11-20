import os
import re
import sqlite3
from pathlib import Path
from functools import wraps

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    request,
    send_file,
    session,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)

# Do not hardcode secrets. Set in environment before starting the app.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required")

DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")
REPORTS_DIRECTORY = Path(
    os.environ.get("REPORTS_DIRECTORY", "./reports")
).resolve()

REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)

# Safe session defaults
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Use HTTPS in production
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)


# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE_PATH)

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    db.commit()
    db.close()


# -----------------------------------------------------------------------------
# Authentication Helpers
# -----------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped


# -----------------------------------------------------------------------------
# Input Validation
# -----------------------------------------------------------------------------

FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def validate_report_name(filename: str) -> str:
    """
    Restricts filenames to a safe character set and length.
    Prevents path traversal and unexpected file access.
    """
    if not filename:
        abort(400, description="Missing filename")

    if not FILENAME_PATTERN.fullmatch(filename):
        abort(400, description="Invalid filename")

    safe_name = secure_filename(filename)

    if not safe_name:
        abort(400, description="Invalid filename")

    return safe_name


def resolve_report_path(filename: str) -> Path:
    """
    Ensures the resolved file remains inside REPORTS_DIRECTORY.
    """
    safe_name = validate_report_name(filename)

    file_path = (REPORTS_DIRECTORY / safe_name).resolve()

    try:
        file_path.relative_to(REPORTS_DIRECTORY)
    except ValueError:
        abort(403, description="Forbidden path")

    return file_path


# -----------------------------------------------------------------------------
# Registration / Login
# -----------------------------------------------------------------------------

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or len(username) > 100:
        return jsonify({"error": "Invalid username"}), 400

    if len(password) < 12:
        return jsonify(
            {"error": "Password must be at least 12 characters"}
        ), 400

    password_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    db = get_db()

    try:
        # Parameterized query
        db.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User registered"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    db = get_db()

    # Parameterized query
    user = db.execute(
        """
        SELECT id, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    session.clear()
    session["user_id"] = user["id"]

    return jsonify({"message": "Login successful"})


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


# -----------------------------------------------------------------------------
# Secure Download Endpoint
# -----------------------------------------------------------------------------

@app.get("/reports/<path:filename>")
@login_required
def download_report(filename):
    """
    Download a report stored on disk.

    Security measures:
    - Authentication required
    - Filename validation
    - Path traversal protection
    - Explicit file existence checks
    """

    report_path = resolve_report_path(filename)

    if not report_path.is_file():
        abort(404, description="Report not found")

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
        conditional=True,
    )


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )