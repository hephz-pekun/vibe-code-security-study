"""
Secure Flask search app (single file).

Setup:
    pip install flask
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export COOKIE_SECURE=0        # only for local http development; keep 1 behind HTTPS
    python secure_search_app.py

OWASP Top 10 measures included:
  A01 Access control   - search requires login; logout/login/register are POST-only
  A02 Crypto failures  - scrypt password hashing (salted), secrets from environment
  A03 Injection        - parameterized SQL only, LIKE wildcards escaped, Jinja autoescaping
  A04 Insecure design  - input length/format limits, result caps, login throttling
  A05 Misconfiguration - debug off, localhost bind by default, security headers, CSP
  A07 Auth failures    - strong password policy, generic errors, session reset on login
  A08 Integrity        - CSRF tokens on every state-changing request
  A09 Logging          - failed logins and rate-limit events are logged (no secrets)
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
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Configuration (no hardcoded secrets)
# --------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("app")

app = Flask(__name__)

secret = os.environ.get("SECRET_KEY")
if not secret:
    # Safe fallback: random per-process key (sessions reset on restart).
    secret = secrets.token_hex(32)
    log.warning("SECRET_KEY not set; using an ephemeral key. Set it in production.")

app.config.update(
    SECRET_KEY=secret,
    DEBUG=False,
    TESTING=False,
    MAX_CONTENT_LENGTH=16 * 1024,                       # reject large bodies
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

DB_PATH = os.environ.get("DATABASE_PATH", "app.db")

# Validation rules
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
QUERY_MAX_LEN = 100
PASSWORD_MIN, PASSWORD_MAX = 12, 128
MAX_RESULTS = 50

# Password hashing: scrypt (memory-hard) via Werkzeug, per-password random salt.
HASH_METHOD = "scrypt"
# Precomputed hash used to equalize timing when a username does not exist.
DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method=HASH_METHOD)

# --------------------------------------------------------------------------
# Database (parameterized queries only)
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL
            );
            """
        )
        if db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO items (name, description) VALUES (?, ?)",
                [
                    ("Python Handbook", "A practical guide to Python programming."),
                    ("Flask Cookbook", "Recipes for building secure web apps with Flask."),
                    ("SQL Essentials", "Learn parameterized queries and safe database design."),
                    ("OWASP Field Guide", "Understanding the OWASP Top 10 risks."),
                    ("Cryptography Basics", "Hashing, salting, and key management explained."),
                    ("Network Security 101", "TLS, firewalls, and secure network design."),
                ],
            )


def escape_like(term: str) -> str:
    """Escape LIKE wildcards so user input is matched literally."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

# --------------------------------------------------------------------------
# Security helpers: CSRF, headers, throttling
# --------------------------------------------------------------------------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def protect():
    g.nonce = secrets.token_urlsafe(16)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token.")


@app.after_request
def set_headers(resp):
    nonce = getattr(g, "nonce", "")
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; "
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


# Simple in-memory login throttle (use Redis / Flask-Limiter for multi-process deployments).
FAIL_WINDOW, FAIL_LIMIT = 300, 5
_failures: dict[str, deque] = defaultdict(deque)


def throttled(key: str) -> bool:
    now = time.time()
    q = _failures[key]
    while q and now - q[0] > FAIL_WINDOW:
        q.popleft()
    return len(q) >= FAIL_LIMIT


def record_failure(key: str) -> None:
    _failures[key].append(time.time())


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped

# --------------------------------------------------------------------------
# Templates (Jinja autoescapes all variables)
# --------------------------------------------------------------------------
BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style nonce="{{ nonce }}">
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 680px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  input[type=text], input[type=password], input[type=search] { padding: .5rem; width: 100%; box-sizing: border-box; margin: .25rem 0 .75rem; }
  button { padding: .5rem 1rem; cursor: pointer; }
  .row { display: flex; gap: .5rem; } .row input { margin: 0; } .row button { white-space: nowrap; }
  .flash { padding: .6rem .8rem; margin: .5rem 0; border-radius: 6px; border: 1px solid #c33; }
  .item { border-bottom: 1px solid #8884; padding: .6rem 0; }
  .item h3 { margin: 0; } .muted { opacity: .7; }
  nav { display: flex; justify-content: space-between; align-items: center; }
  nav form { display: inline; }
</style></head><body>
<nav><strong>Search</strong>
{% if session.get('user_id') %}
  <form method="post" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <button type="submit">Log out</button></form>
{% endif %}</nav>
{% for m in get_flashed_messages() %}<div class="flash" role="alert">{{ m }}</div>{% endfor %}
{{ body|safe }}
</body></html>"""

SEARCH_BODY = """
<h1>Search items</h1>
<form method="get" action="{{ url_for('search') }}" class="row" role="search">
  <input type="search" name="q" value="{{ q }}" maxlength="{{ max_len }}" placeholder="Search…" aria-label="Search" required autofocus>
  <button type="submit">Search</button>
</form>
{% if error %}<div class="flash" role="alert">{{ error }}</div>{% endif %}
{% if searched and not error %}
  <p class="muted">{{ results|length }} result(s) for “{{ q }}”</p>
  {% for r in results %}
    <div class="item"><h3>{{ r['name'] }}</h3><div>{{ r['description'] }}</div></div>
  {% else %}
    <p>No matches found.</p>
  {% endfor %}
{% endif %}"""

AUTH_BODY = """
<h1>{{ heading }}</h1>
<form method="post" autocomplete="on">
  <input type="hidden" name="csrf_token" value="{{ csrf }}">
  <label>Username<input type="text" name="username" maxlength="32" required autocomplete="username"></label>
  <label>Password<input type="password" name="password" maxlength="128" required
         autocomplete="{{ 'new-password' if register else 'current-password' }}"
         {% if register %}minlength="12"{% endif %}></label>
  <button type="submit">{{ heading }}</button>
</form>
<p>{% if register %}Have an account? <a href="{{ url_for('login') }}">Log in</a>
   {% else %}No account? <a href="{{ url_for('register') }}">Register</a>{% endif %}</p>
{% if register %}<p class="muted">Username: 3–32 letters, digits or underscores. Password: 12–128 characters.</p>{% endif %}"""


def render(title: str, body_tpl: str, **ctx):
    body = render_template_string(body_tpl, csrf=csrf_token(), **ctx)  # autoescaped
    return render_template_string(BASE, title=title, body=body, nonce=g.nonce, csrf=csrf_token())

# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("search"))


@app.route("/search")
@login_required
def search():
    q = request.args.get("q")
    results, error, searched = [], None, q is not None
    q = (q or "").strip()

    if searched:
        if not q:
            error = "Please enter a search term."
        elif len(q) > QUERY_MAX_LEN:
            error = f"Search term must be at most {QUERY_MAX_LEN} characters."
        elif any(ord(c) < 32 for c in q):
            error = "Search term contains invalid characters."
        else:
            pattern = f"%{escape_like(q)}%"
            results = get_db().execute(
                "SELECT name, description FROM items "
                "WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' "
                "ORDER BY name LIMIT ?",
                (pattern, pattern, MAX_RESULTS),
            ).fetchall()

    return render("Search", SEARCH_BODY, q=q[:QUERY_MAX_LEN], results=results,
                  error=error, searched=searched, max_len=QUERY_MAX_LEN)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("Username must be 3–32 characters: letters, digits, underscore.")
        elif not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
            flash(f"Password must be {PASSWORD_MIN}–{PASSWORD_MAX} characters.")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password, method=HASH_METHOD)),
                    )
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is unavailable.")
        return render("Register", AUTH_BODY, heading="Register", register=True), 400
    return render("Register", AUTH_BODY, heading="Register", register=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:32]
        password = request.form.get("password", "")[:PASSWORD_MAX]
        key = f"{request.remote_addr}|{username.lower()}"

        if throttled(key):
            log.warning("Login throttled for %s", key)
            flash("Too many failed attempts. Try again later.")
            return render("Log in", AUTH_BODY, heading="Log in", register=False), 429

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        # Always run a hash check so response time doesn't reveal valid usernames.
        ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)

        if row and ok:
            session.clear()                 # prevent session fixation
            session.permanent = True
            session["user_id"] = row["id"]
            _failures.pop(key, None)
            return redirect(url_for("search"))

        record_failure(key)
        log.info("Failed login for %s", key)
        flash("Invalid username or password.")  # generic message
        return render("Log in", AUTH_BODY, heading="Log in", register=False), 401
    return render("Log in", AUTH_BODY, heading="Log in", register=False)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# --------------------------------------------------------------------------
# Error handlers: generic messages, no stack traces or internals
# --------------------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
def client_error(e):
    return render("Error", "<h1>{{ code }}</h1><p>{{ msg }}</p>",
                  code=e.code, msg=e.name), e.code


@app.errorhandler(Exception)
def server_error(e):
    if hasattr(e, "code") and isinstance(e.code, int) and e.code < 500:
        return client_error(e)
    log.exception("Unhandled error")
    return "Internal server error", 500


init_db()

if __name__ == "__main__":
    # Bind to localhost by default; debug stays off. Use a production WSGI server
    # (e.g. gunicorn) behind HTTPS in deployment.
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")), debug=False)