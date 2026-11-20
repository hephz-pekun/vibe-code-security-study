import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps
from pathlib import Path

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
# Configuration & Safe Defaults
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "users.db"))

# Never hardcode production secrets. Require FLASK_SECRET_KEY in production;
# fall back to a per-process random key only when explicitly in debug/dev mode.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    if os.environ.get("FLASK_DEBUG") == "1":
        SECRET_KEY = secrets.token_hex(32)
    else:
        raise RuntimeError(
            "FLASK_SECRET_KEY environment variable must be set. "
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    # Safe cookie defaults (OWASP Session Management)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=True whenever serving over HTTPS (default True unless dev)
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    # Limit request payload size to mitigate DoS via large POST bodies (16 KB)
    MAX_CONTENT_LENGTH=16 * 1024,
)

# ---------------------------------------------------------------------------
# Input Validation Rules
# ---------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


def validate_registration_input(username: str, email: str, password: str, confirm: str) -> list[str]:
    """Validate and constrain user-supplied registration fields."""
    errors = []

    if not USERNAME_REGEX.fullmatch(username):
        errors.append(
            "Username must be 3–30 characters and contain only letters, numbers, or underscores."
        )

    if len(email) > 254 or not EMAIL_REGEX.fullmatch(email):
        errors.append("Please enter a valid email address.")

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters.")
    else:
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        if not (has_upper and has_lower and has_digit):
            errors.append(
                "Password must include at least one uppercase letter, one lowercase letter, and one digit."
            )

    if not secrets.compare_digest(password, confirm):
        errors.append("Passwords do not match.")

    return errors


# ---------------------------------------------------------------------------
# Database Helpers (Parameterized Queries & Least-Privilege Schema)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CSRF Protection & Security Headers
# ---------------------------------------------------------------------------
def get_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def verify_csrf() -> None:
    token = session.get("_csrf_token")
    form_token = request.form.get("_csrf_token", "")
    if not token or not secrets.compare_digest(token, form_token):
        abort(403, description="Invalid or missing CSRF token.")


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';"
    )
    return response


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# Templates (Jinja2 auto-escapes all variables by default against XSS)
# ---------------------------------------------------------------------------
BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 440px; margin: 3rem auto; padding: 0 1rem; color: #1f2937; }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; }
    label { display: block; font-weight: 600; margin-top: 0.9rem; font-size: 0.9rem; }
    input { width: 100%; padding: 0.55rem; margin-top: 0.25rem; border: 1px solid #d1d5db; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 1.25rem; width: 100%; padding: 0.65rem; background: #111827; color: #fff; border: 0; border-radius: 6px; font-weight: 600; cursor: pointer; }
    button:hover { background: #374151; }
    .flash { padding: 0.7rem; border-radius: 6px; margin-bottom: 0.75rem; font-size: 0.9rem; }
    .flash.error { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    .flash.success { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
    .nav { margin-top: 1.25rem; font-size: 0.9rem; text-align: center; }
    small { color: #6b7280; display: block; margin-top: 0.2rem; }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
      <div class="flash {{ category }}">{{ message }}</div>
    {% endfor %}
  {% endwith %}
  {{ content | safe }}
</body>
</html>
"""

REGISTER_FORM = """
<h1>Create an Account</h1>
<form method="post" action="{{ url_for('register') }}" autocomplete="on" novalidate>
  <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">

  <label for="username">Username</label>
  <input id="username" name="username" type="text" value="{{ username }}" required minlength="3" maxlength="30" autocomplete="username">
  <small>3–30 characters: letters, numbers, and underscores only.</small>

  <label for="email">Email</label>
  <input id="email" name="email" type="email" value="{{ email }}" required maxlength="254" autocomplete="email">

  <label for="password">Password</label>
  <input id="password" name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">
  <small>At least 12 characters with uppercase, lowercase, and a number.</small>

  <label for="confirm_password">Confirm Password</label>
  <input id="confirm_password" name="confirm_password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">

  <button type="submit">Register</button>
</form>
<div class="nav">Already have an account? <a href="{{ url_for('login') }}">Log in</a></div>
"""

LOGIN_FORM = """
<h1>Log In</h1>
<form method="post" action="{{ url_for('login') }}" autocomplete="on">
  <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">

  <label for="identifier">Username or Email</label>
  <input id="identifier" name="identifier" type="text" required maxlength="254" autocomplete="username">

  <label for="password">Password</label>
  <input id="password" name="password" type="password" required maxlength="128" autocomplete="current-password">

  <button type="submit">Log In</button>
</form>
<div class="nav">Need an account? <a href="{{ url_for('register') }}">Register</a></div>
"""

DASHBOARD_VIEW = """
<h1>Dashboard</h1>
<p>Signed in as <strong>{{ username }}</strong>.</p>
<form method="post" action="{{ url_for('logout') }}">
  <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Log Out</button>
</form>
"""


def render_page(title: str, inner_template: str, **context) -> str:
    rendered_inner = render_template_string(inner_template, **context)
    return render_template_string(BASE_TEMPLATE, title=title, content=rendered_inner)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    username = ""
    email = ""

    if request.method == "POST":
        verify_csrf()

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = validate_registration_input(username, email, password, confirm)
        if errors:
            for err in errors:
                flash(err, "error")
            return render_page("Register", REGISTER_FORM, username=username, email=email), 400

        # Memory-hard scrypt password hashing with automatic per-user random salt
        password_hash = generate_password_hash(password, method="scrypt")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?);",
                (username, email, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Generic message avoids leaking whether a specific username or email is registered
            flash("An account with that username or email already exists.", "error")
            return render_page("Register", REGISTER_FORM, username=username, email=email), 409

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_page("Register", REGISTER_FORM, username=username, email=email)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        verify_csrf()

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?;",
            (identifier, identifier.lower()),
        ).fetchone()

        # Constant-time dummy hash check prevents timing-based username enumeration
        dummy_hash = (
            "scrypt:32768:8:1$0000000000000000$"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        stored_hash = user["password_hash"] if user else dummy_hash
        password_valid = check_password_hash(stored_hash, password)

        if user and password_valid:
            # Regenerate session state on login to prevent session fixation
            csrf_token = session.get("_csrf_token")
            session.clear()
            if csrf_token:
                session["_csrf_token"] = csrf_token
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid credentials.", "error")
        return render_page("Log In", LOGIN_FORM), 401

    return render_page("Log In", LOGIN_FORM)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_page("Dashboard", DASHBOARD_VIEW, username=session["username"])


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    verify_csrf()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    # Safe default: bind to localhost and disable debug mode unless explicitly enabled
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)