"""
Secure user registration + login for Flask using SQLite.

Setup:
    pip install "flask>=3.0"

Run (development):
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export SESSION_COOKIE_SECURE=0      # only for plain-http local development
    python app.py

Production: run behind HTTPS with a real WSGI server (gunicorn/uwsgi),
keep SESSION_COOKIE_SECURE at its default (on), and use a shared rate limiter
(e.g. Flask-Limiter + Redis) instead of the in-memory one below.
"""

import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import timedelta

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration (secrets come from the environment, never from source code)
# --------------------------------------------------------------------------
app = Flask(__name__)
log = logging.getLogger("app")
logging.basicConfig(level=logging.INFO)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    # Safe fallback: random per-process key. Sessions won't survive restarts
    # or work across multiple workers, so set SECRET_KEY in real deployments.
    secret_key = secrets.token_hex(32)
    log.warning("SECRET_KEY not set; using an ephemeral random key.")

app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "users.db")),
    # Cookie hardening
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") != "0",
    SESSION_COOKIE_NAME="__Host-session" if os.environ.get("SESSION_COOKIE_SECURE", "1") != "0" else "session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    # Reject oversized request bodies (DoS protection)
    MAX_CONTENT_LENGTH=16 * 1024,
    JSON_SORT_KEYS=False,
)
os.makedirs(app.instance_path, exist_ok=True)

# --------------------------------------------------------------------------
# Validation rules
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128  # max length prevents hashing-based DoS
EMAIL_MAX = 254

# Pre-computed hash so login takes similar time whether or not the user exists
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method="scrypt")


def hash_password(password: str) -> str:
    # scrypt: memory-hard KDF with a unique random salt per hash
    return generate_password_hash(password, method="scrypt")


def validate_registration(username: str, email: str, password: str, confirm: str):
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-32 characters: letters, digits, '_', '.', '-'.")
    if len(email) > EMAIL_MAX or not EMAIL_RE.fullmatch(email):
        errors.append("Please enter a valid email address.")
    if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
        errors.append(f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters long.")
    elif password.lower() in {username.lower(), email.lower()}:
        errors.append("Password must not match your username or email.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# --------------------------------------------------------------------------
# Database (parameterized queries only)
# --------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
    try:
        os.chmod(app.config["DATABASE"], 0o600)  # owner-only access
    except OSError:
        pass


# --------------------------------------------------------------------------
# Simple in-memory rate limiter (per IP). Replace with Flask-Limiter in prod.
# --------------------------------------------------------------------------
_attempts = defaultdict(deque)
RATE_LIMIT, RATE_WINDOW = 10, 300  # 10 POSTs per 5 minutes per IP per endpoint


def rate_limited(key: str) -> bool:
    now = time.monotonic()
    q = _attempts[key]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


# --------------------------------------------------------------------------
# CSRF protection + security headers
# --------------------------------------------------------------------------
def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_from_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token.")


@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# --------------------------------------------------------------------------
# Templates (Jinja autoescaping is ON for render_template_string)
# --------------------------------------------------------------------------
BASE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }}</title></head>
<body>
  <nav>
    {% if session.get('user_id') %}
      <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit">Log out</button>
      </form>
    {% else %}
      <a href="{{ url_for('login') }}">Log in</a> |
      <a href="{{ url_for('register') }}">Register</a>
    {% endif %}
  </nav>
  {% for msg in get_flashed_messages() %}<p role="alert">{{ msg }}</p>{% endfor %}
  {{ body|safe }}
</body>
</html>
"""

REGISTER_FORM = """
<h1>Register</h1>
<form method="post" autocomplete="on">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Username <input name="username" required minlength="3" maxlength="32"
         pattern="[A-Za-z0-9_.\\-]+" value="{{ username }}"></label><br>
  <label>Email <input name="email" type="email" required maxlength="254" value="{{ email }}"></label><br>
  <label>Password <input name="password" type="password" required minlength="12"
         maxlength="128" autocomplete="new-password"></label><br>
  <label>Confirm password <input name="confirm" type="password" required minlength="12"
         maxlength="128" autocomplete="new-password"></label><br>
  <button type="submit">Create account</button>
</form>
"""

LOGIN_FORM = """
<h1>Log in</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Username or email <input name="identifier" required maxlength="254"></label><br>
  <label>Password <input name="password" type="password" required maxlength="128"
         autocomplete="current-password"></label><br>
  <button type="submit">Log in</button>
</form>
"""


def page(title: str, body_template: str, **ctx):
    body = render_template_string(body_template, **ctx)  # autoescaped
    return render_template_string(BASE, title=title, body=body)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/")
def index():
    if session.get("user_id"):
        return page("Home", "<h1>Welcome, {{ name }}!</h1>", name=session.get("username"))
    return page("Home", "<h1>Welcome</h1><p>Please log in or register.</p>")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return page("Register", REGISTER_FORM, username="", email="")

    if rate_limited(f"register:{request.remote_addr}"):
        abort(429)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    errors = validate_registration(username, email, password, confirm)
    if errors:
        for e in errors:
            flash(e)
        return page("Register", REGISTER_FORM, username=username, email=email), 400

    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Deliberately vague: don't reveal which field collided
        flash("That username or email is unavailable.")
        return page("Register", REGISTER_FORM, username=username, email=email), 409

    flash("Account created. Please log in.")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("Log in", LOGIN_FORM)

    if rate_limited(f"login:{request.remote_addr}"):
        abort(429)

    identifier = request.form.get("identifier", "").strip()[:EMAIL_MAX]
    password = request.form.get("password", "")[: PASSWORD_MAX + 1]

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?",
        (identifier, identifier.lower()),
    ).fetchone()

    # Always run a hash check so timing doesn't reveal whether the account exists
    stored = user["password_hash"] if user else _DUMMY_HASH
    ok = check_password_hash(stored, password) and user is not None

    if not ok:
        flash("Invalid credentials.")
        return page("Log in", LOGIN_FORM), 401

    session.clear()  # prevent session fixation
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# Error handlers: generic messages, no stack traces or internals leaked
# --------------------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(429)
def client_error(err):
    return page("Error", "<h1>{{ code }}</h1><p>{{ msg }}</p>",
                code=err.code, msg=err.name), err.code


@app.errorhandler(Exception)
def server_error(err):
    if hasattr(err, "code") and isinstance(err.code, int) and err.code < 500:
        return client_error(err)
    log.exception("Unhandled error")
    return page("Error", "<h1>500</h1><p>Something went wrong.</p>"), 500


init_db()

if __name__ == "__main__":
    # debug=False always; bind to localhost by default
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)