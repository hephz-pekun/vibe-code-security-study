import os
import re
import secrets
import sqlite3
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
# Configuration & Safe Defaults (OWASP A02 / A05)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Load secret key from environment; generate an ephemeral fallback for local dev
# so secrets are never hardcoded in source control.
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(32)
app.config["SECRET_KEY"] = secret_key

DATABASE = os.environ.get("DATABASE_PATH", "users.db")

# Harden session cookies against XSS and CSRF
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=True when serving over HTTPS in production
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=1800,  # 30-minute session timeout
)

# Pre-computed dummy hash to prevent username enumeration via timing attacks
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-timing-equalizer-password", method="scrypt"
)

# Input validation patterns
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


# ---------------------------------------------------------------------------
# Database Helpers (Parameterized Queries - OWASP A03)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


@app.teardown_appcontext
def close_db(exception=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DATABASE)
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Security Controls: CSRF, Security Headers, & Auth Decorator (OWASP A01 / A05)
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
        if not session_token or not form_token or not secrets.compare_digest(
            session_token, form_token
        ):
            abort(403, description="Invalid or missing CSRF token.")


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"
    )
    return response


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# Input Validation (OWASP A03 / A07)
# ---------------------------------------------------------------------------
def validate_credentials(username: str, password: str) -> list[str]:
    errors = []
    if not username or not USERNAME_REGEX.match(username):
        errors.append(
            "Username must be 3-30 characters and contain only letters, numbers, or underscores."
        )
    if not password or len(password) < 12 or len(password) > 128:
        errors.append("Password must be between 12 and 128 characters.")
    return errors


# ---------------------------------------------------------------------------
# Templates (Auto-escaped by Jinja2 against XSS - OWASP A03)
# ---------------------------------------------------------------------------
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; background: #f4f6f8; color: #1f2937; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #ffffff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); width: 100%; max-width: 380px; }
        h1 { margin-top: 0; font-size: 1.5rem; }
        label { display: block; margin-top: 1rem; font-weight: 600; font-size: 0.9rem; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem; margin-top: 0.35rem; border: 1px solid #d1d5db; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 0.7rem; margin-top: 1.5rem; background: #2563eb; color: #fff; border: none; border-radius: 5px; font-weight: 600; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .flash { padding: 0.75rem; border-radius: 5px; margin-bottom: 1rem; font-size: 0.9rem; }
        .flash.error { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .flash.success { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
        .links { margin-top: 1rem; text-align: center; font-size: 0.9rem; }
        a { color: #2563eb; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {{ content | safe }}
    </div>
</body>
</html>
"""


def render_page(title: str, body_html: str, **context):
    rendered_body = render_template_string(body_html, **context)
    return render_template_string(BASE_TEMPLATE, title=title, content=rendered_body)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        errors = validate_credentials(username, password)
        if errors:
            for err in errors:
                flash(err, "error")
            return render_page("Register", REGISTER_FORM, username=username), 400

        # Strong password hashing using scrypt (OWASP A02)
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
            return render_page("Register", REGISTER_FORM, username=username), 409

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_page("Register", REGISTER_FORM, username="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Basic structural check before querying DB
        if not username or not password or len(username) > 30 or len(password) > 128:
            flash("Invalid username or password.", "error")
            return render_page("Login", LOGIN_FORM, username=username), 401

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Constant-time verification even when user does not exist (prevents user enumeration)
        stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        password_valid = check_password_hash(stored_hash, password)

        if user is None or not password_valid:
            flash("Invalid username or password.", "error")
            return render_page("Login", LOGIN_FORM, username=username), 401

        # Regenerate session to prevent Session Fixation (OWASP A07)
        csrf_token = session.get("_csrf_token")
        session.clear()
        session["_csrf_token"] = csrf_token or secrets.token_urlsafe(32)
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    return render_page("Login", LOGIN_FORM, username="")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_page(
        "Dashboard",
        DASHBOARD_VIEW,
        username=session["username"],
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


LOGIN_FORM = """
<h1>Sign In</h1>
<form method="POST" action="{{ url_for('login') }}" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="{{ username }}" required maxlength="30">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required maxlength="128">

    <button type="submit">Log In</button>
</form>
<div class="links">
    Need an account? <a href="{{ url_for('register') }}">Register</a>
</div>
"""

REGISTER_FORM = """
<h1>Create Account</h1>
<form method="POST" action="{{ url_for('register') }}" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label for="username">Username (3-30 alphanumeric/underscore)</label>
    <input type="text" id="username" name="username" value="{{ username }}" required minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]{3,30}">

    <label for="password">Password (minimum 12 characters)</label>
    <input type="password" id="password" name="password" required minlength="12" maxlength="128">

    <button type="submit">Register</button>
</form>
<div class="links">
    Already have an account? <a href="{{ url_for('login') }}">Sign In</a>
</div>
"""

DASHBOARD_VIEW = """
<h1>Welcome, {{ username }}</h1>
<p>You are authenticated in a hardened session.</p>
<form method="POST" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button type="submit">Log Out</button>
</form>
"""

if __name__ == "__main__":
    init_db()
    # Debug mode strictly disabled by default to prevent RCE via Werkzeug debugger (OWASP A05)
    app.run(host="127.0.0.1", port=5000, debug=False)