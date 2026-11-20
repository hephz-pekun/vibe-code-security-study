import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from functools import wraps

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
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (OWASP A02, A05)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Load secret key from environment; fall back to an ephemeral key for local dev
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    logging.warning(
        "FLASK_SECRET_KEY not set. Using an ephemeral key; sessions will invalidate on restart."
    )
    secret_key = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=os.environ.get("DATABASE_PATH", "comments.db"),
    # Hardened session cookie flags
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=True when serving over HTTPS (defaulted via env)
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=3600,  # 1-hour session timeout
    MAX_CONTENT_LENGTH=16 * 1024,     # Limit request payload size to 16 KB
)

# Validation constants
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,24}$")
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128
MAX_COMMENT_LEN = 1000

# Simple in-memory sliding-window rate limiter (IP -> list of timestamps)
RATE_LIMIT_STORE: dict[str, list[float]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Database Helpers & Parameterized Queries (OWASP A03)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


@app.teardown_appcontext
def close_db(exception: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        db.commit()


# ---------------------------------------------------------------------------
# Security Middleware: CSRF, Headers & Rate Limiting (OWASP A01, A04, A05)
# ---------------------------------------------------------------------------
def get_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def validate_csrf() -> None:
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        session_token = session.get("_csrf_token")
        form_token = request.form.get("csrf_token")
        if (
            not session_token
            or not form_token
            or not hmac.compare_digest(session_token, form_token)
        ):
            abort(403, description="Invalid or missing CSRF token.")


@app.after_request
def apply_security_headers(response):
    # Prevent MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Control referrer leakage
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Strict Content Security Policy (blocks inline scripts to mitigate XSS)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


def rate_limit(max_requests: int, window_seconds: int):
    """Decorator to throttle repeated requests per client IP."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr or "unknown"
            key = f"{func.__name__}:{client_ip}"
            now = time.monotonic()

            # Prune expired timestamps
            RATE_LIMIT_STORE[key] = [
                ts for ts in RATE_LIMIT_STORE[key] if now - ts < window_seconds
            ]
            if len(RATE_LIMIT_STORE[key]) >= max_requests:
                abort(429, description="Too many requests. Please try again later.")

            RATE_LIMIT_STORE[key].append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to post a comment.", "error")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# HTML Template (Jinja2 Auto-Escaping Active for XSS Protection)
# ---------------------------------------------------------------------------
PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure Comment Board</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; line-height: 1.5; }
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 1rem; margin-bottom: 1.5rem; }
        nav a, nav button { margin-left: 0.75rem; text-decoration: none; color: #2563eb; background: none; border: none; font: inherit; cursor: pointer; padding: 0; }
        .flash { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; }
        .flash.error { background: #fee2e2; color: #991b1b; }
        .flash.success { background: #dcfce7; color: #166534; }
        .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; background: #fafafa; }
        .meta { font-size: 0.85rem; color: #6b7280; margin-bottom: 0.4rem; }
        .comment-body { white-space: pre-wrap; word-break: break-word; }
        form.stacked { display: flex; flex-direction: column; gap: 0.75rem; max-width: 400px; }
        textarea, input { padding: 0.6rem; border: 1px solid #d1d5db; border-radius: 6px; font: inherit; width: 100%; box-sizing: border-box; }
        button.primary { background: #2563eb; color: #fff; border: none; padding: 0.6rem 1.1rem; border-radius: 6px; cursor: pointer; font: inherit; width: fit-content; }
    </style>
</head>
<body>
    <header>
        <strong><a href="{{ url_for('index') }}" style="text-decoration:none;color:inherit;">Comment Board</a></strong>
        <nav>
            {% if session.get('username') %}
                <span>Signed in as <strong>{{ session['username'] }}</strong></span>
                <form action="{{ url_for('logout') }}" method="post" style="display:inline;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <button type="submit">Log out</button>
                </form>
            {% else %}
                <a href="{{ url_for('login') }}">Log in</a>
                <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </nav>
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
            <div class="flash {{ category }}">{{ message }}</div>
        {% endfor %}
    {% endwith %}

    {% if view == 'index' %}
        {% if session.get('user_id') %}
            <form action="{{ url_for('post_comment') }}" method="post" style="margin-bottom: 2rem;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label for="body"><strong>Post a comment</strong></label>
                <textarea id="body" name="body" rows="3" maxlength="{{ max_comment_len }}" required placeholder="Share your thoughts (max {{ max_comment_len }} characters)..."></textarea>
                <div style="margin-top: 0.5rem;">
                    <button type="submit" class="primary">Post Comment</button>
                </div>
            </form>
        {% else %}
            <p><a href="{{ url_for('login') }}">Log in</a> or <a href="{{ url_for('register') }}">create an account</a> to join the discussion.</p>
        {% endif %}

        <h2>Recent Comments</h2>
        {% if comments %}
            {% for comment in comments %}
                <article class="card">
                    <div class="meta">
                        <strong>{{ comment['username'] }}</strong> · {{ comment['created_at'] }} UTC
                    </div>
                    <div class="comment-body">{{ comment['body'] }}</div>
                </article>
            {% endfor %}
        {% else %}
            <p>No comments yet.</p>
        {% endif %}

    {% elif view == 'register' %}
        <h2>Create Account</h2>
        <form action="{{ url_for('register') }}" method="post" class="stacked">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Username (3-24 alphanumeric or underscore)
                <input type="text" name="username" pattern="[a-zA-Z0-9_]{3,24}" required autocomplete="username">
            </label>
            <label>Password (min {{ min_pw_len }} characters)
                <input type="password" name="password" minlength="{{ min_pw_len }}" maxlength="{{ max_pw_len }}" required autocomplete="new-password">
            </label>
            <button type="submit" class="primary">Register</button>
        </form>

    {% elif view == 'login' %}
        <h2>Log In</h2>
        <form action="{{ url_for('login') }}" method="post" class="stacked">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Username
                <input type="text" name="username" required autocomplete="username">
            </label>
            <label>Password
                <input type="password" name="password" required autocomplete="current-password">
            </label>
            <button type="submit" class="primary">Log In</button>
        </form>
    {% endif %}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes & Input Validation (OWASP A01, A03, A07)
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    db = get_db()
    comments = db.execute(
        """
        SELECT c.body, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC
        LIMIT 100
        """
    ).fetchall()
    return render_template_string(
        PAGE_TEMPLATE,
        view="index",
        comments=comments,
        max_comment_len=MAX_COMMENT_LEN,
    )


@app.route("/register", methods=["GET", "POST"])
@rate_limit(max_requests=10, window_seconds=60)
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Strict allowlist validation on username
        if not USERNAME_REGEX.match(username):
            flash(
                "Username must be 3-24 characters using letters, numbers, or underscores.",
                "error",
            )
            return redirect(url_for("register"))

        # Enforce password length bounds
        if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
            flash(
                f"Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters.",
                "error",
            )
            return redirect(url_for("register"))

        # Hash password with strong algorithm (scrypt via Werkzeug)
        password_hash = generate_password_hash(password, method="scrypt")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is already taken.", "error")
            return redirect(url_for("register"))

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template_string(
        PAGE_TEMPLATE,
        view="register",
        min_pw_len=MIN_PASSWORD_LEN,
        max_pw_len=MAX_PASSWORD_LEN,
    )


@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=10, window_seconds=60)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Perform constant-time dummy hash check if user does not exist to prevent user enumeration timing attacks
        if user is None:
            check_password_hash(
                "scrypt:32768:8:1$dummySaltValue$00000000000000000000000000000000",
                password,
            )
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        # Regenerate session state on login to prevent session fixation
        csrf_token = session.get("_csrf_token")
        session.clear()
        if csrf_token:
            session["_csrf_token"] = csrf_token
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Logged in successfully.", "success")
        return redirect(url_for("index"))

    return render_template_string(PAGE_TEMPLATE, view="login")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/comment", methods=["POST"])
@login_required
@rate_limit(max_requests=15, window_seconds=60)
def post_comment():
    body = request.form.get("body", "").strip()

    # Validate presence, length, and strip null bytes
    if not body or "\x00" in body:
        flash("Comment cannot be empty or contain invalid characters.", "error")
        return redirect(url_for("index"))

    if len(body) > MAX_COMMENT_LEN:
        flash(f"Comment cannot exceed {MAX_COMMENT_LEN} characters.", "error")
        return redirect(url_for("index"))

    db = get_db()
    db.execute(
        "INSERT INTO comments (user_id, body) VALUES (?, ?)",
        (session["user_id"], body),
    )
    db.commit()

    flash("Comment posted.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    # Safe default: debug=False prevents interactive debugger exposure
    app.run(host="127.0.0.1", port=5000, debug=False)