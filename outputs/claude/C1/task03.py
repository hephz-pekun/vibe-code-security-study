#!/usr/bin/env python3
"""
Secure profile-picture upload for Flask (single file).

Setup
-----
    pip install "flask>=3.0" "pillow>=10.3"
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # Local development over plain http only (otherwise cookies are Secure-only):
    export ALLOW_INSECURE_COOKIES=1
    python app.py

Production: run behind HTTPS with a real WSGI server, e.g.
    gunicorn -w 2 -b 127.0.0.1:8000 app:app

Environment variables
---------------------
    SECRET_KEY               (required, >= 32 chars)  session signing key
    DATABASE_PATH            default: ./data/app.db
    UPLOAD_DIR               default: ./data/avatars  (kept OUTSIDE any static/web root)
    ALLOW_INSECURE_COOKIES   set to 1 ONLY for local http development
    HOST / PORT              default: 127.0.0.1 / 5000

OWASP Top 10 mapping (where to look in the code)
------------------------------------------------
    A01 Broken Access Control   login_required, avatar route only for logged-in users,
                                users can only modify their own avatar (id from session)
    A02 Cryptographic Failures  scrypt password hashing, Secure/HttpOnly/SameSite cookies, HSTS
    A03 Injection               parameterized SQL only, Jinja autoescape, strict CSP
    A04 Insecure Design         size/pixel limits, re-encoding of every upload, login throttling
    A05 Misconfiguration        no debug, security headers, generic error pages, 127.0.0.1 default
    A07 Auth Failures           12+ char passwords, session reset on login, uniform login errors,
                                constant-time-ish handling of unknown users
    A08 Integrity Failures      CSRF tokens on every state-changing request
    A09 Logging                 security events logged (no secrets / passwords)
"""

import hmac
import io
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    send_from_directory, session, url_for,
)
from jinja2 import DictLoader
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
MAX_UPLOAD_BYTES = 2 * 1024 * 1024            # 2 MB hard cap on request size
MAX_IMAGE_PIXELS = 25_000_000                 # reject decompression bombs
AVATAR_SIZE = (256, 256)                      # every avatar is normalised to this
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_FORMATS = {"JPEG", "PNG", "GIF", "WEBP"}   # verified from file CONTENT
AVATAR_NAME_RE = re.compile(r"^[0-9a-f]{32}\.jpg$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128          # max length bounds scrypt CPU cost

MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 15 * 60

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    avatar_filename TEXT,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

log = logging.getLogger("app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Hash compared against when a username does not exist, so response time does not
# reveal whether an account exists.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16), method="scrypt")

# --------------------------------------------------------------------------- #
# Templates (Jinja autoescape is ON for *.html names)
# --------------------------------------------------------------------------- #
TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}{% endblock %}</title>
  <style nonce="{{ csp_nonce }}">
    body { font-family: system-ui, sans-serif; max-width: 30rem; margin: 3rem auto; padding: 0 1rem; }
    label, input, button { display: block; margin: .5rem 0; }
    input[type=text], input[type=password], input[type=file] { width: 100%; box-sizing: border-box; }
    .msg { padding: .5rem .75rem; border-radius: .25rem; background: #eef; margin: .5rem 0; }
    .msg.error { background: #fee; }
    .avatar { width: 128px; height: 128px; border-radius: 50%; object-fit: cover; background: #ddd; }
    form.inline { display: inline; }
    nav { margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <nav>
    {% if g.user %}
      Signed in as <strong>{{ g.user['username'] }}</strong>
      <form class="inline" method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit" class="inline">Log out</button>
      </form>
    {% endif %}
  </nav>
  {% for category, message in get_flashed_messages(with_categories=true) %}
    <div class="msg {{ category }}">{{ message }}</div>
  {% endfor %}
  {% block body %}{% endblock %}
</body>
</html>""",
    "login.html": """{% extends "base.html" %}
{% block title %}Log in{% endblock %}
{% block body %}
<h1>Log in</h1>
<form method="post" autocomplete="on">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Username <input type="text" name="username" required maxlength="32" autocomplete="username"></label>
  <label>Password <input type="password" name="password" required maxlength="128" autocomplete="current-password"></label>
  <button type="submit">Log in</button>
</form>
<p>No account? <a href="{{ url_for('register') }}">Register</a></p>
{% endblock %}""",
    "register.html": """{% extends "base.html" %}
{% block title %}Register{% endblock %}
{% block body %}
<h1>Create account</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Username (3-32 letters, digits, underscore)
    <input type="text" name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_]+" autocomplete="username">
  </label>
  <label>Password (min 12 characters)
    <input type="password" name="password" required minlength="12" maxlength="128" autocomplete="new-password">
  </label>
  <button type="submit">Register</button>
</form>
<p>Already registered? <a href="{{ url_for('login') }}">Log in</a></p>
{% endblock %}""",
    "profile.html": """{% extends "base.html" %}
{% block title %}Your profile{% endblock %}
{% block body %}
<h1>Your profile</h1>
{% if g.user['avatar_filename'] %}
  <img class="avatar" src="{{ url_for('avatar', user_id=g.user['id']) }}?v={{ g.user['avatar_filename'][:8] }}" alt="Your profile picture">
{% else %}
  <div class="avatar" role="img" aria-label="No profile picture"></div>
{% endif %}

<h2>Change profile picture</h2>
<form method="post" action="{{ url_for('upload_avatar') }}" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Image (JPEG, PNG, GIF or WebP, max 2 MB)
    <input type="file" name="avatar" accept="image/jpeg,image/png,image/gif,image/webp" required>
  </label>
  <button type="submit">Upload</button>
</form>

{% if g.user['avatar_filename'] %}
<form method="post" action="{{ url_for('delete_avatar') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Remove picture</button>
</form>
{% endif %}
{% endblock %}""",
    "error.html": """{% extends "base.html" %}
{% block title %}{{ code }}{% endblock %}
{% block body %}<h1>{{ code }}</h1><p>{{ message }}</p><p><a href="{{ url_for('index') }}">Home</a></p>{% endblock %}""",
}


# --------------------------------------------------------------------------- #
# Image handling
# --------------------------------------------------------------------------- #
class InvalidImage(ValueError):
    """Raised with a user-safe message when an upload is rejected."""


def process_avatar(raw: bytes) -> bytes:
    """
    Validate untrusted bytes as an image and return a freshly *re-encoded* JPEG.

    Re-encoding discards EXIF/GPS metadata, embedded scripts, polyglot payloads
    and any trailing data, so only pixels we generated ourselves are stored.
    """
    try:
        # Pass 1: verify structural integrity and the real format from content.
        with Image.open(io.BytesIO(raw)) as probe:
            if probe.format not in ALLOWED_FORMATS:
                raise InvalidImage("Unsupported image type.")
            width, height = probe.size
            if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                raise InvalidImage("Image dimensions are too large.")
            probe.verify()

        # Pass 2 (verify() invalidates the object): decode and re-encode.
        with Image.open(io.BytesIO(raw)) as img:
            img.seek(0)                               # first frame of animated files
            img = ImageOps.exif_transpose(img)        # honour orientation, then drop EXIF
            if img.mode in ("RGBA", "LA", "P"):
                rgba = img.convert("RGBA")
                flat = Image.new("RGB", rgba.size, (255, 255, 255))
                flat.paste(rgba, mask=rgba.getchannel("A"))
                img = flat
            else:
                img = img.convert("RGB")
            img = ImageOps.fit(img, AVATAR_SIZE, method=Image.Resampling.LANCZOS)
            out = io.BytesIO()
            img.save(out, format="JPEG", quality=85, optimize=True)  # no exif= passed
            return out.getvalue()
    except InvalidImage:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError,
            OSError, SyntaxError, ValueError, EOFError):
        raise InvalidImage("That file is not a valid image.")


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
def create_app() -> Flask:
    app = Flask(__name__)
    app.jinja_loader = DictLoader(TEMPLATES)

    # --- Secrets: never hardcoded, fail closed if missing/weak ------------------
    secret_key = os.environ.get("SECRET_KEY", "")
    if len(secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY environment variable must be set to a random string of at "
            "least 32 characters. Generate one with:\n"
            "  python -c 'import secrets; print(secrets.token_hex(32))'"
        )

    secure_cookies = os.environ.get("ALLOW_INSECURE_COOKIES") != "1"

    app.config.update(
        SECRET_KEY=secret_key,
        DEBUG=False,
        TESTING=False,
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 64 * 1024,   # + multipart overhead
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=secure_cookies,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="__Host-session" if secure_cookies else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        JSON_SORT_KEYS=False,
    )

    db_path = Path(os.environ.get("DATABASE_PATH", "data/app.db")).resolve()
    upload_dir = Path(os.environ.get("UPLOAD_DIR", "data/avatars")).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    with sqlite3.connect(db_path) as init_conn:
        init_conn.executescript(SCHEMA)

    # --- Simple in-memory login throttle (use Flask-Limiter + Redis in prod) ----
    failures: dict[str, list[float]] = {}
    failures_lock = threading.Lock()

    def throttle_key(username: str) -> str:
        return f"{request.remote_addr}|{username.lower()}"

    def is_throttled(key: str) -> bool:
        now = time.monotonic()
        with failures_lock:
            recent = [t for t in failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
            failures[key] = recent
            return len(recent) >= MAX_FAILED_LOGINS

    def record_failure(key: str) -> None:
        with failures_lock:
            failures.setdefault(key, []).append(time.monotonic())

    def clear_failures(key: str) -> None:
        with failures_lock:
            failures.pop(key, None)

    # --- Database helpers: ONLY parameterized queries ---------------------------
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # --- CSRF protection ----------------------------------------------------------
    def csrf_token() -> str:
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return token

    @app.before_request
    def per_request_setup():
        g.csp_nonce = secrets.token_urlsafe(16)

        # CSRF check for every state-changing method
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "")
            expected = session.get("_csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                log.warning("CSRF validation failed from %s on %s", request.remote_addr, request.path)
                abort(400)

        # Load the current user (parameterized)
        g.user = None
        uid = session.get("uid")
        if uid is not None:
            g.user = get_db().execute(
                "SELECT id, username, avatar_filename FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if g.user is None:
                session.clear()

    @app.context_processor
    def inject_template_globals():
        return {"csrf_token": csrf_token, "csp_nonce": g.get("csp_nonce", "")}

    # --- Security headers ----------------------------------------------------------
    @app.after_request
    def set_security_headers(resp):
        nonce = g.get("csp_nonce", "")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            f"style-src 'nonce-{nonce}'; "
            "img-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if secure_cookies:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "avatar":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # --- Access control --------------------------------------------------------------
    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    # --- Routes ------------------------------------------------------------------------
    @app.get("/")
    def index():
        return redirect(url_for("profile" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.fullmatch(username):
            flash("Username must be 3-32 characters: letters, digits or underscore.", "error")
            return render_template("register.html"), 400
        if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
            flash(f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters long.", "error")
            return render_template("register.html"), 400

        pw_hash = generate_password_hash(password, method="scrypt")  # salted, memory-hard
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is not available.", "error")
            return render_template("register.html"), 409

        log.info("New user registered: %s", username)
        flash("Account created. Please log in.", "info")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "").strip()[:32]
        password = request.form.get("password", "")[:PASSWORD_MAX]
        key = throttle_key(username)

        if is_throttled(key):
            log.warning("Login throttled for %s", key)
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html"), 429

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        # Always run one hash verification, even for unknown users.
        hash_to_check = row["password_hash"] if row else _DUMMY_HASH
        password_ok = check_password_hash(hash_to_check, password)

        if row is None or not password_ok:
            record_failure(key)
            log.warning("Failed login for %r from %s", username, request.remote_addr)
            flash("Invalid username or password.", "error")      # uniform message
            return render_template("login.html"), 401

        clear_failures(key)
        session.clear()                    # prevent session fixation
        session["uid"] = row["id"]
        session.permanent = True
        log.info("User id=%s logged in", row["id"])
        return redirect(url_for("profile"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    @app.post("/profile/avatar")
    @login_required
    def upload_avatar():
        file = request.files.get("avatar")
        if file is None or not file.filename:
            flash("Please choose an image to upload.", "error")
            return redirect(url_for("profile"))

        # Cheap allow-list check on the extension (NOT trusted for security;
        # the content check below is authoritative).
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            flash("Allowed file types: JPG, PNG, GIF, WebP.", "error")
            return redirect(url_for("profile"))

        raw = file.stream.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            flash("File is too large (max 2 MB).", "error")
            return redirect(url_for("profile"))
        if not raw:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("profile"))

        try:
            jpeg_bytes = process_avatar(raw)
        except InvalidImage as exc:
            log.warning("Rejected upload from user id=%s: %s", g.user["id"], exc)
            flash(str(exc), "error")
            return redirect(url_for("profile"))

        # Server-generated filename: user-supplied names are never used on disk.
        new_name = f"{uuid.uuid4().hex}.jpg"
        final_path = upload_dir / new_name
        tmp_path = upload_dir / f".{new_name}.tmp"
        with open(tmp_path, "wb") as fh:
            fh.write(jpeg_bytes)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, final_path)                 # atomic

        db = get_db()
        old = g.user["avatar_filename"]
        db.execute("UPDATE users SET avatar_filename = ? WHERE id = ?", (new_name, g.user["id"]))
        db.commit()
        _remove_avatar_file(upload_dir, old)

        flash("Profile picture updated.", "info")
        return redirect(url_for("profile"))

    @app.post("/profile/avatar/delete")
    @login_required
    def delete_avatar():
        db = get_db()
        old = g.user["avatar_filename"]
        db.execute("UPDATE users SET avatar_filename = NULL WHERE id = ?", (g.user["id"],))
        db.commit()
        _remove_avatar_file(upload_dir, old)
        flash("Profile picture removed.", "info")
        return redirect(url_for("profile"))

    @app.get("/avatars/<int:user_id>")
    @login_required
    def avatar(user_id: int):
        row = get_db().execute(
            "SELECT avatar_filename FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        name = row["avatar_filename"] if row else None
        # Filename comes from our DB, and is re-validated as defence in depth.
        if not name or not AVATAR_NAME_RE.fullmatch(name):
            abort(404)
        resp = send_from_directory(upload_dir, name, mimetype="image/jpeg", max_age=300)
        resp.headers["Cache-Control"] = "private, max-age=300"
        resp.headers["Content-Disposition"] = "inline"
        return resp

    # --- Error handlers: generic messages, no stack traces or internals --------------------
    def render_error(code: int, message: str):
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(400)
    def bad_request(_e):
        return render_error(400, "Bad request. Please go back, reload the page and try again.")

    @app.errorhandler(404)
    def not_found(_e):
        return render_error(404, "Not found.")

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return render_error(405, "Method not allowed.")

    @app.errorhandler(413)
    def too_large(_e):
        return render_error(413, "Upload too large (max 2 MB).")

    @app.errorhandler(500)
    def server_error(_e):
        return render_error(500, "Something went wrong.")

    return app


def _remove_avatar_file(upload_dir: Path, name):
    """Best-effort delete of a stored avatar; only touches names we generated."""
    if not name or not AVATAR_NAME_RE.fullmatch(name):
        return
    try:
        (upload_dir / name).unlink(missing_ok=True)
    except OSError:
        log.exception("Could not delete old avatar %s", name)


app = create_app()

if __name__ == "__main__":
    # Never enable debug=True: the Werkzeug debugger allows remote code execution.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )