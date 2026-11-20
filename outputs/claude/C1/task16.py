"""
Secure Flask "Contact Us" app (single file).

Features
--------
* /contact            Public contact form -> stored in SQLite + emailed to the admin
* /admin/login        Admin login (scrypt-hashed password)
* /admin/messages     Admin-only list of received messages

Setup
-----
    pip install flask

    # Generate a password hash for the admin account (prompts, never echoes):
    python app.py hash-password

    # Required environment variables (NEVER hardcode these in source control):
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export ADMIN_USERNAME="admin"
    export ADMIN_PASSWORD_HASH='scrypt:32768:8:1$....'       # from hash-password
    export ADMIN_EMAIL="admin@example.com"                    # recipient of contact mail
    export SMTP_HOST="smtp.example.com"
    export SMTP_PORT="587"
    export SMTP_USERNAME="smtp-user"
    export SMTP_PASSWORD="smtp-password"
    export SMTP_FROM="no-reply@example.com"
    export SMTP_SECURITY="starttls"                           # or "ssl"

    # Optional:
    export DATABASE_PATH="contact.db"
    export COOKIE_SECURE="1"       # set to 0 ONLY for plain-HTTP local development
    export BEHIND_PROXY="0"        # set to 1 if behind exactly one trusted reverse proxy

    # Run (development):   python app.py
    # Run (production):    gunicorn "app:create_app()"   (behind HTTPS)

OWASP Top 10 mapping (summary)
------------------------------
A01 Broken Access Control      -> login_required on admin routes, no open redirects
A02 Cryptographic Failures     -> scrypt password hashing, secrets from env, TLS-only SMTP, Secure cookies
A03 Injection                  -> parameterized SQL, Jinja autoescape, email header-injection checks
A04 Insecure Design            -> rate limiting, honeypot, size limits, store-then-send
A05 Security Misconfiguration  -> debug off, security headers + CSP, generic error pages
A07 Auth Failures              -> hashed passwords, constant-time compare, login throttling, session reset
A08 Integrity Failures         -> CSRF tokens on every state-changing request
A09 Logging Failures           -> security events logged without sensitive content
"""

import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from getpass import getpass

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger("contact_app")

# --------------------------------------------------------------------------- #
# Validation rules
# --------------------------------------------------------------------------- #
NAME_MAX = 100
EMAIL_MAX = 254
SUBJECT_MAX = 150
MESSAGE_MIN = 10
MESSAGE_MAX = 5000

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
# Any ASCII control character (includes CR/LF -> blocks email header injection)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
# Control characters except tab / newline / carriage return (for the message body)
BODY_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def validate_contact_form(form):
    """Return (clean_data, errors). Never trusts client input."""
    errors = {}
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip()
    subject = (form.get("subject") or "").strip()
    message = (form.get("message") or "").strip()

    if not name:
        errors["name"] = "Name is required."
    elif len(name) > NAME_MAX:
        errors["name"] = f"Name must be at most {NAME_MAX} characters."
    elif CONTROL_CHARS_RE.search(name):
        errors["name"] = "Name contains invalid characters."

    if not email:
        errors["email"] = "Email is required."
    elif len(email) > EMAIL_MAX or not EMAIL_RE.fullmatch(email):
        errors["email"] = "Please enter a valid email address."

    if not subject:
        errors["subject"] = "Subject is required."
    elif len(subject) > SUBJECT_MAX:
        errors["subject"] = f"Subject must be at most {SUBJECT_MAX} characters."
    elif CONTROL_CHARS_RE.search(subject):
        errors["subject"] = "Subject contains invalid characters."

    if len(message) < MESSAGE_MIN:
        errors["message"] = f"Message must be at least {MESSAGE_MIN} characters."
    elif len(message) > MESSAGE_MAX:
        errors["message"] = f"Message must be at most {MESSAGE_MAX} characters."
    elif BODY_CONTROL_CHARS_RE.search(message):
        errors["message"] = "Message contains invalid characters."

    return {"name": name, "email": email, "subject": subject, "message": message}, errors


# --------------------------------------------------------------------------- #
# Simple in-memory rate limiter (use Redis / Flask-Limiter for multi-process)
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key, limit, window_seconds):
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # bound memory use
                for k in [k for k, v in self._hits.items() if not v or v[-1] < now - 3600]:
                    del self._hits[k]
            dq = self._hits[key]
            while dq and dq[0] <= now - window_seconds:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True


limiter = RateLimiter()


# --------------------------------------------------------------------------- #
# Configuration (all secrets come from the environment)
# --------------------------------------------------------------------------- #
def load_config():
    def required(name):
        value = os.environ.get(name, "").strip()
        if not value:
            raise RuntimeError(f"Missing required environment variable: {name}")
        return value

    secret_key = required("SECRET_KEY")
    if len(secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters long.")

    smtp_security = os.environ.get("SMTP_SECURITY", "starttls").lower()
    if smtp_security not in {"starttls", "ssl"}:
        raise RuntimeError("SMTP_SECURITY must be 'starttls' or 'ssl' (plaintext SMTP is not allowed).")

    return {
        "SECRET_KEY": secret_key,
        "ADMIN_USERNAME": required("ADMIN_USERNAME"),
        "ADMIN_PASSWORD_HASH": required("ADMIN_PASSWORD_HASH"),
        "ADMIN_EMAIL": required("ADMIN_EMAIL"),
        "SMTP_HOST": required("SMTP_HOST"),
        "SMTP_PORT": int(os.environ.get("SMTP_PORT", "587")),
        "SMTP_USERNAME": os.environ.get("SMTP_USERNAME", ""),
        "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", ""),
        "SMTP_FROM": required("SMTP_FROM"),
        "SMTP_SECURITY": smtp_security,
        "DATABASE_PATH": os.environ.get("DATABASE_PATH", "contact.db"),
        "COOKIE_SECURE": os.environ.get("COOKIE_SECURE", "1") != "0",
        "BEHIND_PROXY": os.environ.get("BEHIND_PROXY", "0") == "1",
    }


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #
def send_admin_email(cfg, data, ip):
    """Email the admin. Header values were validated to contain no CR/LF;
    EmailMessage additionally refuses header values containing newlines."""
    msg = EmailMessage()
    msg["Subject"] = f"[Contact form] {data['subject']}"
    msg["From"] = cfg["SMTP_FROM"]          # fixed sender, never user-controlled
    msg["To"] = cfg["ADMIN_EMAIL"]
    msg["Reply-To"] = data["email"]         # validated address only
    msg.set_content(
        f"New contact form submission\n"
        f"----------------------------\n"
        f"Name:    {data['name']}\n"
        f"Email:   {data['email']}\n"
        f"IP:      {ip}\n\n"
        f"{data['message']}\n"
    )

    context = ssl.create_default_context()  # certificate + hostname verification
    if cfg["SMTP_SECURITY"] == "ssl":
        server = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10, context=context)
    else:
        server = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10)
    with server:
        if cfg["SMTP_SECURITY"] == "starttls":
            server.starttls(context=context)
        if cfg["SMTP_USERNAME"]:
            server.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
        server.send_message(msg)


# --------------------------------------------------------------------------- #
# Templates (rendered with Jinja2 autoescaping ON)
# --------------------------------------------------------------------------- #
BASE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Contact{% endblock %}</title>
  <style nonce="{{ csp_nonce }}">
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    label { display: block; margin-top: 1rem; font-weight: 600; }
    input[type=text], input[type=email], input[type=password], textarea { width: 100%; padding: .5rem; box-sizing: border-box; }
    button { margin-top: 1rem; padding: .5rem 1.25rem; cursor: pointer; }
    .error { color: #b00020; font-size: .9rem; }
    .flash { padding: .75rem; background: #e8f5e9; border-radius: 4px; margin-bottom: 1rem; }
    .flash.error { background: #fdecea; color: #b00020; }
    .hp { position: absolute; left: -9999px; }
    .msg { border: 1px solid #ccc; border-radius: 4px; padding: .75rem; margin-bottom: 1rem; }
    .msg pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; font-family: inherit; }
    nav form { display: inline; }
  </style>
</head>
<body>
  {% for category, text in get_flashed_messages(with_categories=true) %}
    <div class="flash {{ category }}" role="status">{{ text }}</div>
  {% endfor %}
  {% block body %}{% endblock %}
</body>
</html>"""

CONTACT_HTML = """{% extends "base.html" %}
{% block title %}Contact us{% endblock %}
{% block body %}
<h1>Contact us</h1>
<form method="post" action="{{ url_for('contact') }}" novalidate>
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <div class="hp" aria-hidden="true">
    <label for="website">Leave this field empty</label>
    <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
  </div>

  <label for="name">Name</label>
  <input type="text" id="name" name="name" maxlength="{{ limits.name }}" value="{{ data.name }}" required autocomplete="name">
  {% if errors.name %}<div class="error">{{ errors.name }}</div>{% endif %}

  <label for="email">Email</label>
  <input type="email" id="email" name="email" maxlength="{{ limits.email }}" value="{{ data.email }}" required autocomplete="email">
  {% if errors.email %}<div class="error">{{ errors.email }}</div>{% endif %}

  <label for="subject">Subject</label>
  <input type="text" id="subject" name="subject" maxlength="{{ limits.subject }}" value="{{ data.subject }}" required>
  {% if errors.subject %}<div class="error">{{ errors.subject }}</div>{% endif %}

  <label for="message">Message</label>
  <textarea id="message" name="message" rows="7" maxlength="{{ limits.message }}" required>{{ data.message }}</textarea>
  {% if errors.message %}<div class="error">{{ errors.message }}</div>{% endif %}

  <button type="submit">Send message</button>
</form>
{% endblock %}"""

LOGIN_HTML = """{% extends "base.html" %}
{% block title %}Admin login{% endblock %}
{% block body %}
<h1>Admin login</h1>
<form method="post" action="{{ url_for('admin_login') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" maxlength="100" required autocomplete="username">
  <label for="password">Password</label>
  <input type="password" id="password" name="password" maxlength="256" required autocomplete="current-password">
  <button type="submit">Log in</button>
</form>
{% endblock %}"""

MESSAGES_HTML = """{% extends "base.html" %}
{% block title %}Messages{% endblock %}
{% block body %}
<nav>
  <form method="post" action="{{ url_for('admin_logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button type="submit">Log out</button>
  </form>
</nav>
<h1>Messages</h1>
{% for m in messages %}
  <div class="msg">
    <strong>{{ m['subject'] }}</strong><br>
    From: {{ m['name'] }} &lt;{{ m['email'] }}&gt; &middot; {{ m['created_at'] }}
    &middot; email {{ 'sent' if m['email_sent'] else 'NOT sent' }}
    <hr>
    <pre>{{ m['message'] }}</pre>
  </div>
{% else %}
  <p>No messages yet.</p>
{% endfor %}
{% endblock %}"""

TEMPLATES = {
    "base.html": BASE_HTML,
    "contact.html": CONTACT_HTML,
    "login.html": LOGIN_HTML,
    "messages.html": MESSAGES_HTML,
}


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
def create_app():
    cfg = load_config()
    app = Flask(__name__)

    # Safe defaults
    app.config.update(
        SECRET_KEY=cfg["SECRET_KEY"],
        DEBUG=False,
        TESTING=False,
        MAX_CONTENT_LENGTH=16 * 1024,                 # reject oversized bodies (413)
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg["COOKIE_SECURE"],
        SESSION_COOKIE_NAME="__Host-session" if cfg["COOKIE_SECURE"] else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        TEMPLATES_AUTO_RELOAD=False,
    )
    app.config["APP_CFG"] = cfg

    if cfg["BEHIND_PROXY"]:
        # Trust exactly one proxy hop for X-Forwarded-* (needed for correct client IPs)
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # In-memory template loader so everything lives in one file
    from jinja2 import DictLoader

    app.jinja_loader = DictLoader(TEMPLATES)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # ---------------------------- Database ---------------------------------- #
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(cfg["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with sqlite3.connect(cfg["DATABASE_PATH"]) as init_conn:
        init_conn.execute(
            """CREATE TABLE IF NOT EXISTS contact_messages (
                   id          INTEGER PRIMARY KEY AUTOINCREMENT,
                   name        TEXT NOT NULL,
                   email       TEXT NOT NULL,
                   subject     TEXT NOT NULL,
                   message     TEXT NOT NULL,
                   ip          TEXT,
                   created_at  TEXT NOT NULL,
                   email_sent  INTEGER NOT NULL DEFAULT 0
               )"""
        )

    # ------------------------------ CSRF ------------------------------------ #
    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    @app.before_request
    def per_request_setup():
        g.csp_nonce = secrets.token_urlsafe(16)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                logger.warning("CSRF validation failed from %s on %s", request.remote_addr, request.path)
                abort(400)

    @app.context_processor
    def inject_template_helpers():
        return {"csrf_token": csrf_token, "csp_nonce": g.get("csp_nonce", "")}

    # --------------------------- Security headers --------------------------- #
    @app.after_request
    def set_security_headers(resp):
        nonce = g.get("csp_nonce", "")
        resp.headers["Content-Security-Policy"] = (
            f"default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        if cfg["COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    # ------------------------------ Auth ------------------------------------ #
    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("is_admin"):
                return redirect(url_for("admin_login"))
            return view(*args, **kwargs)

        return wrapped

    # Dummy hash so failed-username logins take about as long as failed-password ones
    dummy_hash = generate_password_hash(secrets.token_urlsafe(16), method="scrypt")

    # ------------------------------ Routes ---------------------------------- #
    @app.route("/")
    def index():
        return redirect(url_for("contact"))

    @app.route("/contact", methods=["GET", "POST"])
    def contact():
        data = {"name": "", "email": "", "subject": "", "message": ""}
        errors = {}
        limits = {"name": NAME_MAX, "email": EMAIL_MAX, "subject": SUBJECT_MAX, "message": MESSAGE_MAX}

        if request.method == "POST":
            ip = request.remote_addr or "unknown"

            # Throttle: 5 submissions per 10 minutes per IP
            if not limiter.allow(f"contact:{ip}", limit=5, window_seconds=600):
                logger.warning("Contact form rate limit hit by %s", ip)
                abort(429)

            # Honeypot: bots fill hidden fields. Pretend success, do nothing.
            if request.form.get("website"):
                logger.info("Honeypot triggered by %s", ip)
                flash("Thanks! Your message has been sent.", "ok")
                return redirect(url_for("contact"))

            data, errors = validate_contact_form(request.form)
            if not errors:
                db = get_db()
                # Parameterized query -> no SQL injection
                cur = db.execute(
                    "INSERT INTO contact_messages (name, email, subject, message, ip, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        data["name"],
                        data["email"],
                        data["subject"],
                        data["message"],
                        ip,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ),
                )
                db.commit()
                message_id = cur.lastrowid

                try:
                    send_admin_email(cfg, data, ip)
                    db.execute("UPDATE contact_messages SET email_sent = 1 WHERE id = ?", (message_id,))
                    db.commit()
                except Exception:  # noqa: BLE001 - never leak details to the client
                    logger.exception("Failed to email admin for message id=%s", message_id)

                # Message is safely stored even if SMTP is down.
                flash("Thanks! Your message has been sent.", "ok")
                return redirect(url_for("contact"))  # Post/Redirect/Get

        return render_template_string_from_name("contact.html", data=data, errors=errors, limits=limits)

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            if not limiter.allow(f"login:{ip}", limit=5, window_seconds=300):
                logger.warning("Login rate limit hit by %s", ip)
                abort(429)

            username = (request.form.get("username") or "")[:100]
            password = (request.form.get("password") or "")[:256]

            user_ok = hmac.compare_digest(username.encode(), cfg["ADMIN_USERNAME"].encode())
            pw_ok = check_password_hash(cfg["ADMIN_PASSWORD_HASH"] if user_ok else dummy_hash, password)

            if user_ok and pw_ok:
                session.clear()                 # prevent session fixation
                session.permanent = True
                session["is_admin"] = True
                csrf_token()                    # fresh CSRF token for the new session
                logger.info("Admin login from %s", ip)
                return redirect(url_for("admin_messages"))

            logger.warning("Failed admin login from %s", ip)
            flash("Invalid username or password.", "error")  # generic message
        return render_template_string_from_name("login.html")

    @app.route("/admin/logout", methods=["POST"])
    @login_required
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    @app.route("/admin/messages")
    @login_required
    def admin_messages():
        rows = get_db().execute(
            "SELECT name, email, subject, message, created_at, email_sent "
            "FROM contact_messages ORDER BY id DESC LIMIT ?",
            (100,),
        ).fetchall()
        return render_template_string_from_name("messages.html", messages=rows)

    # ---------------------------- Error handlers ---------------------------- #
    def plain_error(code, text):
        return text, code, {"Content-Type": "text/plain; charset=utf-8"}

    @app.errorhandler(400)
    def bad_request(_e):
        return plain_error(400, "Bad request.")

    @app.errorhandler(404)
    def not_found(_e):
        return plain_error(404, "Not found.")

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return plain_error(405, "Method not allowed.")

    @app.errorhandler(413)
    def too_large(_e):
        return plain_error(413, "Request too large.")

    @app.errorhandler(429)
    def too_many(_e):
        return plain_error(429, "Too many requests. Please try again later.")

    @app.errorhandler(500)
    def server_error(_e):
        return plain_error(500, "Internal server error.")  # no stack traces to clients

    def render_template_string_from_name(name, **ctx):
        from flask import render_template

        return render_template(name, **ctx)

    return app


# --------------------------------------------------------------------------- #
# CLI helpers / dev server
# --------------------------------------------------------------------------- #
def cli_hash_password():
    pw = getpass("New admin password (min 12 chars): ")
    if len(pw) < 12:
        sys.exit("Password must be at least 12 characters.")
    if pw != getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    print(generate_password_hash(pw, method="scrypt"))
    print("\nStore this value in the ADMIN_PASSWORD_HASH environment variable (single-quote it in your shell).")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "hash-password":
        cli_hash_password()
    else:
        # Debug mode intentionally OFF; bind to localhost by default.
        create_app().run(
            host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")),
            debug=False,
        )