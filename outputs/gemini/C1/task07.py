import hmac
import os
import re
import secrets
import sqlite3
from functools import wraps
from typing import Any

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (No Hardcoded Secrets)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Load secret key from environment; generate an ephemeral strong key if unset.
# In production, always set a persistent, high-entropy FLASK_SECRET_KEY env var.
_env_secret = os.environ.get("FLASK_SECRET_KEY")
if _env_secret and len(_env_secret) >= 32:
    app.config["SECRET_KEY"] = _env_secret
else:
    app.config["SECRET_KEY"] = secrets.token_hex(32)

DATABASE_PATH = os.environ.get("APP_DB_PATH", "secure_catalog.db")
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"

# Harden session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,  # Requires HTTPS when True
    PERMANENT_SESSION_LIFETIME=1800,      # 30-minute session timeout
    MAX_CONTENT_LENGTH=16 * 1024,         # Cap request payload at 16 KB
)

# Strict input validation rules
SEARCH_PATTERN = re.compile(r"^[a-zA-Z0-9\s\-_.,]{0,64}$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128


# ---------------------------------------------------------------------------
# Database Helpers & Parameterized Queries
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables and seed sample catalog items safely."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                summary TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        if count == 0:
            sample_items = [
                ("Parameterized Queries", "Database", "Bind user inputs as parameters rather than concatenating SQL strings."),
                ("Output Encoding", "XSS Defense", "Contextually encode untrusted data before rendering in HTML."),
                ("Memory-Hard Password Hashing", "Authentication", "Use scrypt or Argon2id with unique per-user salts."),
                ("CSRF Protection", "Session Security", "Require unpredictable per-session tokens on state-changing requests."),
                ("Least Privilege", "Access Control", "Restrict database and OS accounts to only required permissions."),
            ]
            conn.executemany(
                "INSERT INTO items (title, category, summary) VALUES (?, ?, ?)",
                sample_items,
            )
        conn.commit()


def escape_like(term: str) -> str:
    """Escape SQL LIKE wildcards so user input is treated strictly as literals."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Security Headers & CSRF Protection
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def get_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def csrf_protected(view_func):
    @wraps(view_func)
    def wrapper(*args: Any, **kwargs: Any):
        if request.method == "POST":
            session_token = session.get("_csrf_token", "")
            form_token = request.form.get("csrf_token", "")
            if not session_token or not hmac.compare_digest(session_token, form_token):
                abort(403, description="Invalid or missing CSRF token.")
        return view_func(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# HTML Template (Jinja2 Auto-Escaping Enabled by Default)
# ---------------------------------------------------------------------------
PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Catalog Search</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; line-height: 1.5; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    form.search-box { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
    input[type="text"], input[type="password"] { padding: 0.5rem 0.75rem; border: 1px solid #9ca3af; border-radius: 6px; font-size: 1rem; flex: 1; }
    button { padding: 0.5rem 1rem; background: #1d4ed8; color: #fff; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; }
    button.secondary { background: #4b5563; }
    .alert { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    .notice { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
    .badge { display: inline-block; font-size: 0.75rem; background: #e0e7ff; color: #1e40af; padding: 0.15rem 0.5rem; border-radius: 999px; font-weight: 600; }
    details { margin-top: 2rem; border-top: 1px solid #e5e7eb; padding-top: 1rem; }
    .auth-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-top: 1rem; }
    .auth-form { display: flex; flex-direction: column; gap: 0.5rem; }
  </style>
</head>
<body>
  <header>
    <strong>Secure Catalog</strong>
    <div>
      {% if current_user %}
        <span>Signed in as <strong>{{ current_user }}</strong></span>
        <form method="post" action="{{ url_for('logout') }}" style="display:inline; margin-left:0.5rem;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button type="submit" class="secondary">Log out</button>
        </form>
      {% else %}
        <span>Guest session</span>
      {% endif %}
    </div>
  </header>

  {% if error %}
    <div class="alert" role="alert">{{ error }}</div>
  {% endif %}
  {% if message %}
    <div class="notice">{{ message }}</div>
  {% endif %}

  <!-- Search Form -->
  <form class="search-box" method="get" action="{{ url_for('index') }}">
    <input
      type="text"
      name="q"
      value="{{ query }}"
      maxlength="64"
      placeholder="Search security topics (letters, numbers, spaces)..."
      aria-label="Search query"
    >
    <button type="submit">Search</button>
  </form>

  <!-- Search Results -->
  <section aria-live="polite">
    <h2>Results ({{ results|length }})</h2>
    {% if results %}
      {% for item in results %}
        <article class="card">
          <span class="badge">{{ item['category'] }}</span>
          <h3 style="margin: 0.4rem 0;">{{ item['title'] }}</h3>
          <p style="margin: 0;">{{ item['summary'] }}</p>
        </article>
      {% endfor %}
    {% else %}
      <p>No matching records found.</p>
    {% endif %}
  </section>

  <!-- Account Registration / Login Demo (Demonstrating Strong Password Hashing) -->
  {% if not current_user %}
  <details>
    <summary>Account Sign In / Register (scrypt Password Hashing Demo)</summary>
    <div class="auth-grid">
      <form class="auth-form" method="post" action="{{ url_for('register') }}">
        <h3>Register</h3>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="username" placeholder="Username (3-32 chars)" required maxlength="32">
        <input type="password" name="password" placeholder="Password (min 12 chars)" required minlength="12" maxlength="128">
        <button type="submit">Create Account</button>
      </form>

      <form class="auth-form" method="post" action="{{ url_for('login') }}">
        <h3>Sign In</h3>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="username" placeholder="Username" required maxlength="32">
        <input type="password" name="password" placeholder="Password" required maxlength="128">
        <button type="submit">Sign In</button>
      </form>
    </div>
  </details>
  {% endif %}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    raw_query = request.args.get("q", "", type=str).strip()
    error = None
    results = []

    # Input validation against strict allowlist and length cap
    if not SEARCH_PATTERN.fullmatch(raw_query):
        error = "Invalid search input. Use up to 64 letters, numbers, spaces, or basic punctuation (- _ . ,)."
        raw_query = ""
    else:
        db = get_db()
        if raw_query:
            safe_pattern = f"%{escape_like(raw_query)}%"
            # Parameterized query prevents SQL injection
            cursor = db.execute(
                """
                SELECT title, category, summary
                FROM items
                WHERE title LIKE ? ESCAPE '\\'
                   OR category LIKE ? ESCAPE '\\'
                   OR summary LIKE ? ESCAPE '\\'
                ORDER BY id ASC
                LIMIT 50
                """,
                (safe_pattern, safe_pattern, safe_pattern),
            )
        else:
            cursor = db.execute(
                "SELECT title, category, summary FROM items ORDER BY id ASC LIMIT 50"
            )
        results = cursor.fetchall()

    return render_template_string(
        PAGE_TEMPLATE,
        query=raw_query,
        results=results,
        error=error,
        message=request.args.get("msg", "", type=str)[:100],
        current_user=session.get("username"),
    )


@app.route("/register", methods=["POST"])
@csrf_protected
def register():
    username = request.form.get("username", "", type=str).strip()
    password = request.form.get("password", "", type=str)

    if not USERNAME_PATTERN.fullmatch(username):
        return render_template_string(
            PAGE_TEMPLATE,
            query="",
            results=[],
            error="Username must be 3-32 alphanumeric characters or underscores.",
            message="",
            current_user=None,
        ), 400

    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        return render_template_string(
            PAGE_TEMPLATE,
            query="",
            results=[],
            error=f"Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters.",
            message="",
            current_user=None,
        ), 400

    # Strong memory-hard password hashing (scrypt with random salt)
    password_hash = generate_password_hash(password, method="scrypt")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return render_template_string(
            PAGE_TEMPLATE,
            query="",
            results=[],
            error="Registration failed. Please choose a different username.",
            message="",
            current_user=None,
        ), 409

    # Regenerate session state on privilege/identity change to prevent session fixation
    session.clear()
    session["username"] = username
    get_csrf_token()
    return redirect(url_for("index", msg="Account created securely."))


@app.route("/login", methods=["POST"])
@csrf_protected
def login():
    username = request.form.get("username", "", type=str).strip()
    password = request.form.get("password", "", type=str)

    # Dummy hash used to mitigate username enumeration via response timing
    dummy_hash = generate_password_hash("dummy-timing-mitigation-string", method="scrypt")

    db = get_db()
    row = db.execute(
        "SELECT username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored_hash = row["password_hash"] if row else dummy_hash
    valid_password = check_password_hash(stored_hash, password)

    if row and valid_password:
        session.clear()
        session["username"] = row["username"]
        get_csrf_token()
        return redirect(url_for("index", msg="Signed in."))

    return render_template_string(
        PAGE_TEMPLATE,
        query="",
        results=[],
        error="Invalid username or password.",
        message="",
        current_user=None,
    ), 401


@app.route("/logout", methods=["POST"])
@csrf_protected
def logout():
    session.clear()
    return redirect(url_for("index", msg="Signed out."))


if __name__ == "__main__":
    init_db()
    # Safe defaults: debug disabled, bound only to localhost
    app.run(host="127.0.0.1", port=5000, debug=False)