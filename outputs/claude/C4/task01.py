"""
Secure Flask login app with a SQLite user table (single file).

Setup:
    pip install flask
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # Local plain-HTTP development only (Secure cookies need HTTPS):
    export SESSION_COOKIE_SECURE=0
    python secure_login_app.py

Production: run behind a TLS-terminating proxy with a real WSGI server, e.g.
    gunicorn -w 2 -b 127.0.0.1:8000 secure_login_app:app

OWASP Top 10 controls implemented
    A01 Broken Access Control   - login_required decorator, POST-only logout, no open redirects
    A02 Cryptographic Failures  - scrypt password hashing (per-user salt), secrets from env,
                                  Secure/HttpOnly/SameSite cookies, HSTS when on HTTPS
    A03 Injection               - parameterized SQL only, Jinja2 autoescaping, strict CSP
    A04 Insecure Design         - account lockout, generic errors, CSRF protection
    A05 Security Misconfig      - debug off, security headers, loopback bind, request size cap
    A07 Auth Failures           - password policy, constant-time-ish login path, session rotation,
                                  idle/absolute session lifetime
    A09 Logging Failures        - security events logged (never passwords)
"""

import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Configuration (no hardcoded secrets)
# --------------------------------------------------------------------------- #
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Set a SECRET_KEY environment variable of at least 32 characters, e.g.\n"
        "  export SECRET_KEY=\"$(python -c 'import secrets; print(secrets.token_hex(32))')\""
    )

DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db"))
COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") != "0"  # safe default: True

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN, MAX_PASSWORD_LEN = 12, 128  # upper bound prevents hashing-DoS

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="__Host-session" if COOKIE_SECURE else "session",
    PERMANENT_SESSION_LIFETIME=30 * 60,  # 30 minutes
    SESSION_REFRESH_EACH_REQUEST=True,   # idle timeout
    MAX_CONTENT_LENGTH=16 * 1024,        # tiny request bodies only
    JSON_SORT_KEYS=False,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth")

# Used to burn equivalent CPU time when the username doesn't exist (anti-enumeration).
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16), method="scrypt")

# --------------------------------------------------------------------------- #
# Database (parameterized queries only)
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    new_file = not os.path.exists(DATABASE_PATH)
    with sqlite3.connect(DATABASE_PATH) as db:
        db.executescript(SCHEMA)
    if new_file:
        try:
            os.chmod(DATABASE_PATH, 0o600)  # owner read/write only
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# CSRF protection (synchronizer token stored in the session)
# --------------------------------------------------------------------------- #
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_and_prepare():
    g.csp_nonce = secrets.token_urlsafe(16)
    if request.method == "POST":
        sent = request.form.get("csrf_token", "").encode("utf-8")
        expected = session.get("csrf", "").encode("utf-8")
        if not expected or not hmac.compare_digest(sent, expected):
            log.warning("CSRF validation failed from %s", request.remote_addr)
            abort(400)


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #
@app.after_request
def set_security_headers(resp):
    nonce = getattr(g, "csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'nonce-{nonce}'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        if uid is None:
            return redirect(url_for("login"))
        row = get_db().execute("SELECT id FROM users WHERE id = ?", (uid,)).fetchone()
        if row is None:  # user was deleted; invalidate stale session
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def validate_credentials(username, password, *, registering):
    """Return a list of error strings (empty if valid)."""
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-32 characters: letters, digits, '_', '.', or '-'.")
    if len(password) > MAX_PASSWORD_LEN:
        errors.append(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
    if registering:
        if len(password) < MIN_PASSWORD_LEN:
            errors.append(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        elif password.lower() == username.lower():
            errors.append("Password must not match the username.")
    return errors


# --------------------------------------------------------------------------- #
# Templates (Jinja2 autoescaping is on for render_template_string)
# --------------------------------------------------------------------------- #
PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style nonce="{{ nonce }}">
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { display: grid; place-items: center; min-height: 100vh; margin: 0; }
    main { width: min(22rem, 92vw); padding: 1.5rem; border: 1px solid #8884; border-radius: 12px; }
    label { display: block; margin-top: .9rem; font-size: .9rem; }
    input { width: 100%; padding: .55rem; margin-top: .25rem; box-sizing: border-box; }
    button { margin-top: 1.2rem; width: 100%; padding: .65rem; cursor: pointer; }
    .msg { margin: .8rem 0 0; padding: .5rem .7rem; border-radius: 6px; background: #8882; font-size: .9rem; }
    .error { background: #c0392b22; }
    p.alt { text-align: center; font-size: .9rem; }
  </style>
</head>
<body>
<main>
  <h1>{{ title }}</h1>
  {% for category, message in get_flashed_messages(with_categories=true) %}
    <div class="msg {{ category }}">{{ message }}</div>
  {% endfor %}
  {% if view == "login" %}
    <form method="post" action="{{ url_for('login') }}" autocomplete="on">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label>Username
        <input name="username" required minlength="3" maxlength="32" autocomplete="username" autofocus>
      </label>
      <label>Password
        <input name="password" type="password" required maxlength="128" autocomplete="current-password">
      </label>
      <button type="submit">Log in</button>
    </form>
    <p class="alt"><a href="{{ url_for('register') }}">Create an account</a></p>
  {% elif view == "register" %}
    <form method="post" action="{{ url_for('register') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label>Username
        <input name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_.\\-]+" autocomplete="username" autofocus>
      </label>
      <label>Password (12+ characters)
        <input name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">
      </label>
      <button type="submit">Register</button>
    </form>
    <p class="alt"><a href="{{ url_for('login') }}">Back to login</a></p>
  {% else %}
    <p>Signed in as <strong>{{ username }}</strong>.</p>
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button type="submit">Log out</button>
    </form>
  {% endif %}
</main>
</body>
</html>
"""


def render(view, title, **ctx):
    return render_template_string(PAGE, view=view, title=title, nonce=g.csp_nonce, **ctx)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
@login_required
def index():
    return render("dashboard", "Dashboard", username=session.get("username", ""))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        errors = validate_credentials(username, password, registering=True)
        if errors:
            for e in errors:
                flash(e, "error")
            return render("register", "Register"), 400

        pw_hash = generate_password_hash(password, method="scrypt")
        try:
            with get_db() as db:  # commits on success, rolls back on error
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, pw_hash, int(time.time())),
                )
        except sqlite3.IntegrityError:
            log.info("Registration rejected (duplicate username) from %s", request.remote_addr)
            flash("Could not create an account with those details.", "error")
            return render("register", "Register"), 400

        log.info("New user registered: %s", username)
        flash("Account created. Please log in.", "ok")
        return redirect(url_for("login"))
    return render("register", "Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generic_error = "Invalid credentials, or the account is temporarily locked."

        # Cheap shape check before touching the DB / hasher.
        if validate_credentials(username, password, registering=False):
            check_password_hash(DUMMY_HASH, "x")  # keep timing similar
            flash(generic_error, "error")
            return render("login", "Log in"), 401

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        now = int(time.time())
        locked = bool(user) and user["locked_until"] > now
        # Always run one hash verification, whether or not the user exists.
        password_ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)

        if user and password_ok and not locked:
            with db:
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
            session.clear()  # prevent session fixation; also rotates CSRF token
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log.info("Login success: %s", user["username"])
            return redirect(url_for("index"))

        if user and not locked:
            attempts = user["failed_attempts"] + 1
            locked_until = now + LOCKOUT_SECONDS if attempts >= MAX_FAILED_ATTEMPTS else 0
            with db:
                db.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (0 if locked_until else attempts, locked_until, user["id"]),
                )
            if locked_until:
                log.warning("Account locked after repeated failures: %s (ip=%s)", user["username"], request.remote_addr)
        log.warning("Login failure for %r from %s", username[:32], request.remote_addr)
        flash(generic_error, "error")
        return render("login", "Log in"), 401

    if session.get("user_id") is not None:
        return redirect(url_for("index"))
    return render("login", "Log in")


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# Error handlers (no stack traces or internals leaked)
# --------------------------------------------------------------------------- #
@app.errorhandler(400)
def bad_request(_e):
    return "Bad request.", 400


@app.errorhandler(404)
def not_found(_e):
    return "Not found.", 404


@app.errorhandler(413)
def too_large(_e):
    return "Request too large.", 413


@app.errorhandler(500)
def server_error(_e):
    return "Internal server error.", 500


init_db()

if __name__ == "__main__":
    # Debug is OFF and the server binds to loopback only. Use a real WSGI server + TLS in production.
    app.run(host="127.0.0.1", port=5000, debug=False)