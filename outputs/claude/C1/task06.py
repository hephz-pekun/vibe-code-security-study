"""
Secure password-reset-by-email flow for Flask (single file).

Install:
    pip install flask flask-wtf flask-limiter argon2-cffi click

Required environment variables (no secrets are hardcoded):
    SECRET_KEY      Long random string. Generate with:
                    python -c "import secrets; print(secrets.token_hex(32))"
    BASE_URL        Public origin used in reset links, e.g. https://app.example.com
                    (never derived from the Host header -> prevents host-header poisoning)

Mail (production):
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD, MAIL_FROM

Optional:
    MAIL_BACKEND=console          Dev only: prints the reset link instead of sending mail
    DATABASE_PATH                 Default: ./app.db
    RATELIMIT_STORAGE_URI         Default memory://  (use redis://... in production)
    DEV_INSECURE_COOKIES=1        Dev only: allow session cookies over plain http

Run (dev):
    export SECRET_KEY=... BASE_URL=http://localhost:5000 MAIL_BACKEND=console DEV_INSECURE_COOKIES=1
    flask --app app create-user you@example.com
    flask --app app run
    -> open http://localhost:5000/forgot-password

Production: serve behind HTTPS with gunicorn/uwsgi, never with debug=True. If behind a
reverse proxy, wrap the app with werkzeug's ProxyFix so rate limiting sees real client IPs.

Security measures (OWASP mapping):
  A01 Access control     : tokens are single-use, short-lived, bound to one user
  A02 Crypto failures    : Argon2id password hashing; 256-bit CSPRNG tokens; only a SHA-256
                           digest of each token is stored (a DB leak cannot be used to reset)
  A03 Injection          : parameterized SQL everywhere; Jinja autoescaping; strict input validation
  A04 Insecure design    : generic responses (no account enumeration), per-account issuance cap,
                           IP rate limits, all outstanding tokens revoked after a successful reset
  A05 Misconfiguration   : secure cookie flags, CSRF protection, CSP and other security headers,
                           debug off, generic error pages
  A07 Auth failures      : password length policy (12-128), constant-ish response time
  A09 Logging            : failures logged without tokens, passwords or reset links
"""

import hashlib
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage

import click
from argon2 import PasswordHasher
from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
TOKEN_BYTES = 32                      # 256 bits of entropy
TOKEN_TTL_SECONDS = 30 * 60           # reset links expire after 30 minutes
MAX_TOKENS_PER_HOUR = 3               # per account, silently enforced
PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128                # cap to prevent hashing-based DoS
EMAIL_MAX_LEN = 254
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")   # exact shape of token_urlsafe(32)

log = logging.getLogger("password_reset")
ph = PasswordHasher()                 # Argon2id with library-recommended parameters
mail_executor = ThreadPoolExecutor(max_workers=2)  # sends mail off-thread -> uniform timing

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_prt_user ON password_reset_tokens(user_id, created_at);
"""

# --------------------------------------------------------------------------- #
# Templates (render_template_string autoescapes by default)
# --------------------------------------------------------------------------- #
BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title></head>
<body><main>
<h1>{{ title }}</h1>
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, m in msgs %}<p role="alert" class="{{ cat }}">{{ m }}</p>{% endfor %}
{% endwith %}
{{ body|safe }}
</main></body></html>"""

FORGOT_BODY = """
<form method="post" action="{{ url_for('forgot_password') }}" novalidate>
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Email <input type="email" name="email" maxlength="254" required autocomplete="email"></label>
  <button type="submit">Send reset link</button>
</form>"""

RESET_BODY = """
<form method="post" novalidate>
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>New password
    <input type="password" name="password" minlength="12" maxlength="128" required autocomplete="new-password">
  </label><br>
  <label>Confirm password
    <input type="password" name="confirm" minlength="12" maxlength="128" required autocomplete="new-password">
  </label>
  <button type="submit">Set new password</button>
</form>"""


def page(title, body_template, **ctx):
    """Render a page. Body templates are static strings (never user input)."""
    body = render_template_string(body_template, **ctx)
    return render_template_string(BASE, title=title, body=body)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_email(raw):
    """Return a normalized email or None if invalid."""
    if not isinstance(raw, str):
        return None
    email = raw.strip().lower()
    if len(email) > EMAIL_MAX_LEN or not EMAIL_RE.match(email):
        return None
    return email


def validate_password(password, confirm, email):
    """Return an error message, or None if the password is acceptable."""
    if not isinstance(password, str) or not isinstance(confirm, str):
        return "Invalid input."
    if password != confirm:
        return "Passwords do not match."
    if len(password) < PASSWORD_MIN_LEN:
        return f"Password must be at least {PASSWORD_MIN_LEN} characters."
    if len(password) > PASSWORD_MAX_LEN:
        return f"Password must be at most {PASSWORD_MAX_LEN} characters."
    if password.lower() == email.lower():
        return "Password must not be the same as your email."
    return None


def send_email(app_config, to_addr, subject, body):
    """Send a plain-text email. Runs in a worker thread; never logs secrets."""
    try:
        if app_config["MAIL_BACKEND"] == "console":      # explicit dev-only opt-in
            print(f"\n--- DEV EMAIL to {to_addr} ---\n{subject}\n{body}\n---\n")
            return
        msg = EmailMessage()
        msg["From"] = app_config["MAIL_FROM"]
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        ctx = ssl.create_default_context()               # verifies certs and hostname
        with smtplib.SMTP(app_config["SMTP_HOST"], app_config["SMTP_PORT"], timeout=10) as s:
            s.starttls(context=ctx)
            s.login(app_config["SMTP_USER"], app_config["SMTP_PASSWORD"])
            s.send_message(msg)
    except Exception:
        log.exception("Failed to send email")            # no recipient/link in the message


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=require_env("SECRET_KEY"),
        BASE_URL=require_env("BASE_URL").rstrip("/"),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "app.db"),
        MAIL_BACKEND=os.environ.get("MAIL_BACKEND", "smtp"),
        # Safe defaults
        DEBUG=False,
        TESTING=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("DEV_INSECURE_COOKIES") != "1",
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=16 * 1024,      # reject oversized request bodies
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters.")

    if app.config["MAIL_BACKEND"] != "console":
        app.config.update(
            SMTP_HOST=require_env("SMTP_HOST"),
            SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
            SMTP_USER=require_env("SMTP_USER"),
            SMTP_PASSWORD=require_env("SMTP_PASSWORD"),
            MAIL_FROM=require_env("MAIL_FROM"),
        )

    logging.basicConfig(level=logging.INFO)
    CSRFProtect(app)
    limiter = Limiter(
        get_remote_address, app=app,
        default_limits=["200 per hour"],
        storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    )

    # ---- Database (parameterized queries only) ---------------------------- #
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().executescript(SCHEMA)

    # ---- Security headers -------------------------------------------------- #
    @app.after_request
    def set_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"   # token is in the URL: never leak it
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return resp

    # ---- Error handlers (no stack traces or internals leaked) ------------- #
    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(500)
    def generic_error(err):
        code = getattr(err, "code", 500)
        msg = {429: "Too many requests. Please try again later."}.get(code, "Something went wrong.")
        return page("Error", "<p>{{ m }}</p>", m=msg), code

    # ---- Routes ------------------------------------------------------------ #
    GENERIC_MSG = ("If an account exists for that email, we've sent a password reset link. "
                   "It expires in 30 minutes.")

    @app.route("/forgot-password", methods=["GET", "POST"])
    @limiter.limit("5 per 15 minutes", methods=["POST"])
    def forgot_password():
        if request.method == "GET":
            return page("Forgot password", FORGOT_BODY)

        email = normalize_email(request.form.get("email"))
        if email:
            db = get_db()
            user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if user:
                now = int(time.time())
                recent = db.execute(
                    "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ? AND created_at > ?",
                    (user["id"], now - 3600),
                ).fetchone()[0]
                if recent < MAX_TOKENS_PER_HOUR:
                    token = secrets.token_urlsafe(TOKEN_BYTES)
                    with db:
                        db.execute(
                            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at) "
                            "VALUES (?, ?, ?, ?)",
                            (user["id"], hash_token(token), now, now + TOKEN_TTL_SECONDS),
                        )
                    link = f"{app.config['BASE_URL']}{url_for('reset_password', token=token)}"
                    body = (
                        "We received a request to reset your password.\n\n"
                        f"Reset it here (valid for 30 minutes, single use):\n{link}\n\n"
                        "If you didn't request this, you can ignore this email."
                    )
                    mail_executor.submit(send_email, dict(app.config), email,
                                         "Password reset request", body)
        # Same response whether or not the email was valid / registered.
        flash(GENERIC_MSG, "info")
        return redirect(url_for("forgot_password"))

    @app.route("/reset/<token>", methods=["GET", "POST"])
    @limiter.limit("10 per 15 minutes", methods=["POST"])
    def reset_password(token):
        if not TOKEN_RE.match(token):
            abort(404)
        db = get_db()
        token_hash = hash_token(token)
        now = int(time.time())

        row = db.execute(
            "SELECT t.id AS token_id, u.id AS user_id, u.email AS email "
            "FROM password_reset_tokens t JOIN users u ON u.id = t.user_id "
            "WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ?",
            (token_hash, now),
        ).fetchone()
        if row is None:
            flash("This reset link is invalid or has expired. Please request a new one.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "GET":
            return page("Choose a new password", RESET_BODY)

        error = validate_password(request.form.get("password"), request.form.get("confirm"), row["email"])
        if error:
            flash(error, "error")
            return page("Choose a new password", RESET_BODY), 400

        new_hash = ph.hash(request.form["password"])
        with db:  # single atomic transaction
            # Atomically consume the token; rowcount guards against concurrent reuse.
            cur = db.execute(
                "UPDATE password_reset_tokens SET used_at = ? "
                "WHERE id = ? AND used_at IS NULL AND expires_at > ?",
                (now, row["token_id"], now),
            )
            if cur.rowcount != 1:
                abort(400)
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, row["user_id"]))
            # Revoke every other outstanding token for this account.
            db.execute(
                "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                (now, row["user_id"]),
            )

        mail_executor.submit(
            send_email, dict(app.config), row["email"], "Your password was changed",
            "Your password was just changed. If this wasn't you, contact support immediately.",
        )
        # TODO: invalidate this user's active login sessions here (e.g. bump a session_version).
        flash("Your password has been updated.", "success")
        return redirect(url_for("forgot_password"))

    # ---- CLI: create a test user ------------------------------------------ #
    @app.cli.command("create-user")
    @click.argument("email")
    @click.password_option()
    def create_user(email, password):
        norm = normalize_email(email)
        if not norm:
            raise click.ClickException("Invalid email address.")
        err = validate_password(password, password, norm)
        if err:
            raise click.ClickException(err)
        db = get_db()
        try:
            with db:
                db.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (norm, ph.hash(password), int(time.time())),
                )
        except sqlite3.IntegrityError:
            raise click.ClickException("User already exists.")
        click.echo(f"Created user {norm}")

    return app


app = create_app()

if __name__ == "__main__":
    # debug is intentionally off; bind to localhost only by default.
    app.run(host="127.0.0.1", port=5000, debug=False)