"""
Flask download endpoint for per-user reports stored on disk.

Layout on disk:
    REPORTS_DIR/
        <user_id>/
            q3-summary.pdf
            sales_2026.csv

Endpoints:
    POST /login                       demo login (REPLACE with your real auth)
    POST /logout
    GET  /reports                     list the current user's reports
    GET  /reports/<filename>          download one of the current user's reports
                                      (add ?inline=1 to view in-browser instead)

Run:
    pip install flask
    export SECRET_KEY="change-me"
    python report_download.py
"""

import logging
import mimetypes
import os
import re
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    request,
    send_file,
    session,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", BASE_DIR / "reports")).resolve()

# Only these file types can ever be served.
ALLOWED_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".docx", ".txt", ".json"}

# Conservative filename whitelist: letters, digits, dot, dash, underscore, space.
# Rejects "/", "\", "..", null bytes, etc. before we ever touch the filesystem.
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\- ]{0,199}$")

# User IDs are used as directory names, so they get the same treatment.
SAFE_USER_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# Types that are safe to render inline in a browser. Everything else is
# always forced to download (prevents stored-XSS via html/svg/etc.).
INLINE_SAFE_MIMETYPES = {"application/pdf", "text/plain", "text/csv"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # request bodies only; downloads unaffected
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("reports")


# --------------------------------------------------------------------------- #
# Authentication (demo - swap for Flask-Login, JWT, SSO, etc.)
# --------------------------------------------------------------------------- #

# Demo credential store. NEVER do this in production: use hashed passwords
# in a real database.
DEMO_USERS = {
    "alice": "alice-password",
    "bob": "bob-password",
}


def current_user_id():
    """Return the authenticated user's id, or None."""
    user_id = session.get("user_id")
    if user_id and SAFE_USER_ID_RE.fullmatch(user_id):
        return user_id
    return None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user_id() is None:
            return jsonify(error="authentication required"), 401
        return view(*args, **kwargs)

    return wrapper


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if DEMO_USERS.get(username) == password and SAFE_USER_ID_RE.fullmatch(username):
        session.clear()
        session["user_id"] = username
        return jsonify(status="ok")
    return jsonify(error="invalid credentials"), 401


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(status="ok")


# --------------------------------------------------------------------------- #
# Path resolution helpers
# --------------------------------------------------------------------------- #

def user_report_dir(user_id: str) -> Path:
    """Directory holding a given user's reports (not guaranteed to exist)."""
    return REPORTS_DIR / user_id


def resolve_report_path(user_id: str, filename: str) -> Path | None:
    """
    Map (user, filename) to a real file on disk, or return None if the request
    is invalid, escapes the user's directory, or doesn't exist.

    Defence in depth:
      1. Whitelist regex on the filename
      2. Extension allowlist
      3. resolve() + is_relative_to() so symlinks / odd paths can't escape
      4. Must be a regular file
    """
    if not SAFE_FILENAME_RE.fullmatch(filename):
        return None
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return None

    user_dir = user_report_dir(user_id).resolve()
    candidate = (user_dir / filename).resolve()

    if not candidate.is_relative_to(user_dir):
        return None
    if not candidate.is_file():
        return None
    return candidate


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@app.get("/reports")
@login_required
def list_reports():
    user_id = current_user_id()
    user_dir = user_report_dir(user_id)

    reports = []
    if user_dir.is_dir():
        for entry in sorted(user_dir.iterdir()):
            path = resolve_report_path(user_id, entry.name)
            if path is None:
                continue
            stat = path.stat()
            reports.append(
                {
                    "filename": path.name,
                    "size_bytes": stat.st_size,
                    "modified": stat.st_mtime,
                    "download_url": f"/reports/{path.name}",
                }
            )
    return jsonify(reports=reports)


@app.get("/reports/<path:filename>")
@login_required
def download_report(filename: str):
    user_id = current_user_id()
    path = resolve_report_path(user_id, filename)

    # Same 404 for "doesn't exist", "not yours" and "invalid name" so we never
    # reveal which files exist for other users.
    if path is None:
        log.warning("report not found/denied: user=%s filename=%r", user_id, filename)
        abort(404)

    mimetype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    want_inline = request.args.get("inline") == "1"
    as_attachment = not (want_inline and mimetype in INLINE_SAFE_MIMETYPES)

    log.info("report download: user=%s file=%s", user_id, path.name)

    response = send_file(
        path,
        mimetype=mimetype,
        as_attachment=as_attachment,
        download_name=path.name,
        conditional=True,  # Range / If-Modified-Since / ETag support
        max_age=0,
    )
    # Reports are private: never let shared caches store them.
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not found"), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify(error="method not allowed"), 405


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    # Create a sample report for the demo user so the endpoint can be tried.
    sample_dir = user_report_dir("alice")
    sample_dir.mkdir(parents=True, exist_ok=True)
    sample_file = sample_dir / "hello.txt"
    if not sample_file.exists():
        sample_file.write_text("Hello from Alice's report.\n")

    # Use a production WSGI server (gunicorn/uwsgi) instead of this in prod.
    app.run(host="127.0.0.1", port=5000, debug=False)