"""
Secure comment board (Flask + SQLite), single file.

Setup:
    pip install "flask>=3.0"
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # Local development over plain http only:
    export ALLOW_INSECURE_COOKIES=1
    python comment_board.py

Production: run behind HTTPS with a real WSGI server, e.g.
    gunicorn -w 2 'comment_board:create_app()'
and leave ALLOW_INSECURE_COOKIES unset.

Environment variables:
    SECRET_KEY               (required) session signing key, never hardcoded
    DATABASE_PATH            (optional) default: comments.db
    ALLOW_INSECURE_COOKIES   (optional) set to 1 ONLY for local http dev
    HOST / PORT              (optional) dev server bind, default 127.0.0.1:5000
"""

import hmac
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import defaultdict, deque

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Constants / validation rules
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128      # max length prevents hashing-DoS
COMMENT_MIN, COMMENT_MAX = 1, 1000
PAGE_SIZE = 20

# Password hashing: Werkzeug's scrypt (memory-hard, per-password random salt).
HASH_METHOD = "scrypt"
# Used to equalize timing when a username does not exist (anti-enumeration).
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16), method=HASH_METHOD)

# Simple in-memory login throttle (per process). Use Redis/Flask-Limiter in prod.
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
_failed_logins = defaultdict(deque)

log = logging.getLogger("comment_board")

# --------------------------------------------------------------------------
# Templates (Jinja2 autoescaping is ON for .html names -> XSS protection)
# --------------------------------------------------------------------------
TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Comment Board</title>
  <link rel="stylesheet" href="{{ url_for('stylesheet') }}">
</head>
<body>
<header>
  <h1><a href="{{ url_for('index') }}">Comment Board</a></h1>
  <nav>
  {% if session.get('user_id') %}
    <span>Signed in as <strong>{{ session.get('username') }}</strong></span>
    <form method="post" action="{{ url_for('logout') }}" class="inline">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button type="submit">Log out</button>
    </form>
  {% else %}
    <a href="{{ url_for('login') }}">Log in</a> |
    <a href="{{ url_for('register') }}">Register</a>
  {% endif %}
  </nav>
</header>
<main>
  {% for category, message in get_flashed_messages(with_categories=true) %}
    <p class="flash {{ category }}">{{ message }}</p>
  {% endfor %}
  {% block content %}{% endblock %}
</main>
</body>
</html>""",

    "index.html": """{% extends "base.html" %}
{% block content %}
{% if session.get('user_id') %}
  <form method="post" action="{{ url_for('post_comment') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label for="body">Add a comment (max """ + str(COMMENT_MAX) + """ characters)</label>
    <textarea id="body" name="body" rows="4" maxlength=\"""" + str(COMMENT_MAX) + """\" required></textarea>
    <button type="submit">Post</button>
  </form>
{% else %}
  <p>Please <a href="{{ url_for('login') }}">log in</a> to post a comment.</p>
{% endif %}

<h2>Comments</h2>
{% for c in comments %}
  <article class="comment">
    <div class="meta"><strong>{{ c['username'] }}</strong> &middot; {{ c['created_at'] }} UTC</div>
    <p class="body">{{ c['body'] }}</p>
    {% if session.get('user_id') == c['user_id'] %}
      <form method="post" action="{{ url_for('delete_comment', comment_id=c['id']) }}" class="inline">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit">Delete</button>
      </form>
    {% endif %}
  </article>
{% else %}
  <p>No comments yet.</p>
{% endfor %}

<nav class="pager">
  {% if page > 1 %}<a href="{{ url_for('index', page=page-1) }}">&laquo; Newer</a>{% endif %}
  {% if has_next %}<a href="{{ url_for('index', page=page+1) }}">Older &raquo;</a>{% endif %}
</nav>
{% endblock %}""",

    "auth.html": """{% extends "base.html" %}
{% block content %}
<h2>{{ title }}</h2>
<form method="post" autocomplete="on">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label for="username">Username</label>
  <input id="username" name="username" type="text" maxlength="30"
         autocomplete="username" required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" maxlength="{{ pw_max }}"
         autocomplete="{{ 'new-password' if register else 'current-password' }}" required>
  {% if register %}
    <small>Username: 3-30 letters, digits or underscores. Password: {{ pw_min }}+ characters.</small>
  {% endif %}
  <button type="submit">{{ title }}</button>
</form>
{% endblock %}""",

    "error.html": """{% extends "base.html" %}
{% block content %}
<h2>{{ code }}</h2>
<p>{{ message }}</p>
<p><a href="{{ url_for('index') }}">Back to the board</a></p>
{% endblock %}""",
}

# Served from our own origin so the CSP can forbid inline styles/scripts.
CSS = """
body{font-family:system-ui,sans-serif;max-width:720px;margin:0 auto;padding:1rem;line-height:1.5}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #ccc}
header h1 a{text-decoration:none;color:inherit}
label{display:block;margin-top:.8rem;font-weight:600}
input[type=text],input[type=password],textarea{width:100%;padding:.5rem;box-sizing:border-box}
button{margin-top:.6rem;padding:.4rem .9rem;cursor:pointer}
form.inline{display:inline}form.inline button{margin:0 0 0 .5rem}
.comment{border:1px solid #ddd;border-radius:6px;padding:.6rem .9rem;margin:.7rem 0}
.comment .meta{color:#555;font-size:.85rem}
.comment .body{white-space:pre-wrap;overflow-wrap:anywhere;margin:.4rem 0}
.flash{padding:.5rem .8rem;border-radius:4px;background:#eef}
.flash.error{background:#fee}.flash.success{background:#efe}
.pager a{margin-right:1rem}
"""


# --------------------------------------------------------------------------
# Database helpers (ALL queries are parameterized)
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g_app().config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def g_app():
    from flask import current_app
    return current_app


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body       TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 1000),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_comments_created ON comments(id DESC);
            """
        )
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(path, 0o600)  # DB readable only by the app user
    except OSError:
        pass


# --------------------------------------------------------------------------
# Security helpers
# --------------------------------------------------------------------------
def csrf_token():
    """Per-session CSRF token, created lazily."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def client_key(username):
    return f"{request.remote_addr}|{username.lower()}"


def too_many_failures(key):
    now = time.monotonic()
    attempts = _failed_logins[key]
    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= LOGIN_MAX_FAILURES


def record_failure(key):
    _failed_logins[key].append(time.monotonic())


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def clean_text(value, max_len):
    """Normalize line endings, strip, and drop control chars (keep \\n, \\t)."""
    value = (value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    value = "".join(ch for ch in value if ch in "\n\t" or ch.isprintable())
    return value[:max_len + 1]  # +1 so over-long input is still detectable


# --------------------------------------------------------------------------
# Application factory
# --------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.jinja_loader = DictLoader(TEMPLATES)

    # --- Secrets: from environment only, never hardcoded ---
    secret = os.environ.get("SECRET_KEY")
    if not secret or len(secret) < 32:
        sys.exit("SECRET_KEY environment variable is required (>= 32 chars). "
                 "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'")

    insecure_cookies = os.environ.get("ALLOW_INSECURE_COOKIES") == "1"

    # --- Safe defaults ---
    app.config.update(
        SECRET_KEY=secret,
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "comments.db"),
        DEBUG=False,
        TESTING=False,
        MAX_CONTENT_LENGTH=16 * 1024,            # small request bodies only
        SESSION_COOKIE_HTTPONLY=True,            # no JS access to the cookie
        SESSION_COOKIE_SAMESITE="Lax",           # CSRF defense in depth
        SESSION_COOKIE_SECURE=not insecure_cookies,  # HTTPS only by default
        PERMANENT_SESSION_LIFETIME=2 * 60 * 60,  # 2-hour sessions
        TEMPLATES_AUTO_RELOAD=False,
    )

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db(app.config["DATABASE_PATH"])
    app.teardown_appcontext(close_db)
    app.jinja_env.globals["csrf_token"] = csrf_token

    # ----------------------------------------------------------------------
    # Request hooks
    # ----------------------------------------------------------------------
    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "")
            expected = session.get("_csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400, description="Invalid or missing CSRF token.")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if not insecure_cookies:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "stylesheet":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ----------------------------------------------------------------------
    # Routes
    # ----------------------------------------------------------------------
    @app.get("/style.css")
    def stylesheet():
        return Response(CSS, mimetype="text/css",
                        headers={"Cache-Control": "public, max-age=3600"})

    @app.get("/")
    def index():
        try:
            page = max(1, min(int(request.args.get("page", 1)), 10_000))
        except ValueError:
            page = 1
        offset = (page - 1) * PAGE_SIZE
        rows = get_db().execute(
            """SELECT c.id, c.user_id, c.body, c.created_at, u.username
               FROM comments c JOIN users u ON u.id = c.user_id
               ORDER BY c.id DESC LIMIT ? OFFSET ?""",
            (PAGE_SIZE + 1, offset),
        ).fetchall()
        return render_template("index.html", comments=rows[:PAGE_SIZE],
                               has_next=len(rows) > PAGE_SIZE, page=page)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            error = None
            if not USERNAME_RE.fullmatch(username):
                error = "Username must be 3-30 letters, digits or underscores."
            elif not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
                error = f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters."

            if error is None:
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password, method=HASH_METHOD)),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    error = "That username is not available."
            if error is None:
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            flash(error, "error")
        return render_template("auth.html", title="Register", register=True,
                               pw_min=PASSWORD_MIN, pw_max=PASSWORD_MAX)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()[:30]
            password = (request.form.get("password") or "")[:PASSWORD_MAX]
            key = client_key(username)

            if too_many_failures(key):
                log.warning("Login throttled for %s", key)
                abort(429)

            row = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            # Always run one hash verification so timing doesn't reveal
            # whether the username exists.
            stored = row["password_hash"] if row else DUMMY_HASH
            valid = check_password_hash(stored, password) and row is not None

            if valid:
                _failed_logins.pop(key, None)
                session.clear()                 # prevent session fixation
                session.permanent = True
                session["user_id"] = row["id"]
                session["username"] = row["username"]
                csrf_token()                    # fresh CSRF token for new session
                return redirect(url_for("index"))  # fixed target: no open redirect

            record_failure(key)
            flash("Invalid username or password.", "error")  # generic message
        return render_template("auth.html", title="Log in", register=False,
                               pw_min=PASSWORD_MIN, pw_max=PASSWORD_MAX)

    @app.post("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("index"))

    @app.post("/comments")
    @login_required
    def post_comment():
        body = clean_text(request.form.get("body"), COMMENT_MAX)
        if len(body) < COMMENT_MIN:
            flash("Comment cannot be empty.", "error")
        elif len(body) > COMMENT_MAX:
            flash(f"Comment must be at most {COMMENT_MAX} characters.", "error")
        else:
            db = get_db()
            db.execute("INSERT INTO comments (user_id, body) VALUES (?, ?)",
                       (session["user_id"], body))
            db.commit()
            flash("Comment posted.", "success")
        return redirect(url_for("index"))

    @app.post("/comments/<int:comment_id>/delete")
    @login_required
    def delete_comment(comment_id):
        db = get_db()
        # Ownership enforced in the query itself (prevents IDOR / broken access control).
        cur = db.execute("DELETE FROM comments WHERE id = ? AND user_id = ?",
                         (comment_id, session["user_id"]))
        db.commit()
        if cur.rowcount == 0:
            abort(404)
        flash("Comment deleted.", "success")
        return redirect(url_for("index"))

    # ----------------------------------------------------------------------
    # Error handlers: generic messages, no stack traces or internals leaked
    # ----------------------------------------------------------------------
    messages = {
        400: "Bad request.",
        404: "Not found.",
        405: "Method not allowed.",
        413: "Request too large.",
        429: "Too many attempts. Please wait a few minutes and try again.",
        500: "Something went wrong on our side.",
    }

    def make_handler(code):
        def handler(_err):
            return render_template("error.html", code=code,
                                   message=messages[code]), code
        return handler

    for status in messages:
        app.register_error_handler(status, make_handler(status))

    @app.errorhandler(Exception)
    def unhandled(err):
        from werkzeug.exceptions import HTTPException
        if isinstance(err, HTTPException):
            return render_template("error.html", code=err.code,
                                   message="Request could not be completed."), err.code
        log.exception("Unhandled error")  # details go to logs only
        return render_template("error.html", code=500, message=messages[500]), 500

    return app


if __name__ == "__main__":
    # Development server only. Binds to localhost by default; debug stays OFF.
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"),
                     port=int(os.environ.get("PORT", "5000")),
                     debug=False)