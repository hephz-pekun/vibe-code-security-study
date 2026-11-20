import functools
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
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

# ---------------------------------------------------------------------------
# 1. Configuration & Secret Management (No Hardcoded Secrets)
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)

    secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not secret_key or len(secret_key) < 32:
        raise RuntimeError(
            "FLASK_SECRET_KEY environment variable must be set and at least 32 characters long. "
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )

    # Safe defaults: default to production-grade secure cookies; require explicit opt-out for local HTTP
    is_secure_cookie = os.environ.get("FLASK_ENV_HTTP_ONLY_DEV", "false").lower() != "true"

    app.config.update(
        SECRET_KEY=secret_key,
        DATABASE=os.environ.get("DATABASE_PATH", "app.db"),
        # __Host- prefix locks cookie to exact origin (requires Secure=True, Path='/', no Domain)
        SESSION_COOKIE_NAME="__Host-session" if is_secure_cookie else "session",
        SESSION_COOKIE_HTTPONLY=True,          # Blocks JavaScript access (XSS mitigation)
        SESSION_COOKIE_SECURE=is_secure_cookie, # Transmits only over HTTPS
        SESSION_COOKIE_SAMESITE="Lax",         # Defense-in-depth against CSRF
        SESSION_COOKIE_PATH="/",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=True,
        MAX_CONTENT_LENGTH=16 * 1024,          # Cap request payload at 16 KB
    )

    # Argon2id hasher (OWASP recommended password hashing algorithm)
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MiB
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    # Pre-computed dummy hash for constant-time login mitigation against user enumeration
    DUMMY_HASH = ph.hash("dummy-password-for-timing-equalization")

    # -----------------------------------------------------------------------
    # 2. Database Layer (Parameterized Queries Only)
    # -----------------------------------------------------------------------

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"])
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(exception: Optional[BaseException] = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db() -> None:
        with sqlite3.connect(app.config["DATABASE"]) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS active_sessions (
                    session_token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
                """
            )

    init_db()

    # -----------------------------------------------------------------------
    # 3. Input Validation Helpers
    # -----------------------------------------------------------------------

    USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")

    def validate_credentials(username: str, password: str) -> Optional[str]:
        if not username or not USERNAME_RE.match(username):
            return "Username must be 3-32 characters (letters, numbers, underscores only)."
        if not password or len(password) < 12 or len(password) > 128:
            return "Password must be between 12 and 128 characters."
        return None

    # -----------------------------------------------------------------------
    # 4. Security Headers, CSRF Protection & Session Verification
    # -----------------------------------------------------------------------

    def get_csrf_token() -> str:
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.before_request
    def enforce_csrf_and_session_integrity() -> None:
        # 1. Verify CSRF token on all state-changing HTTP methods
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected_token = session.get("_csrf_token", "")
            submitted_token = request.form.get("csrf_token", "")
            if not expected_token or not hmac.compare_digest(expected_token, submitted_token):
                abort(403, description="Invalid or missing CSRF token.")

        # 2. Validate server-side session revocation & expiry
        g.user = None
        user_id = session.get("user_id")
        session_token = session.get("session_token")

        if user_id and session_token:
            db = get_db()
            row = db.execute(
                """
                SELECT u.id, u.username, s.expires_at
                FROM active_sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.session_token = ? AND s.user_id = ?
                """,
                (session_token, user_id),
            ).fetchone()

            now = datetime.now(timezone.utc)
            if row is None or datetime.fromisoformat(row["expires_at"]) <= now:
                # Session expired or revoked server-side: wipe cookie
                db.execute("DELETE FROM active_sessions WHERE session_token = ?", (session_token,))
                db.commit()
                session.clear()
            else:
                g.user = {"id": row["id"], "username": row["username"]}
                # Slide expiration window forward
                new_expiry = (now + app.config["PERMANENT_SESSION_LIFETIME"]).isoformat()
                db.execute(
                    "UPDATE active_sessions SET expires_at = ? WHERE session_token = ?",
                    (new_expiry, session_token),
                )
                db.commit()

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none';"
        )
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapped_view(*args: Any, **kwargs: Any) -> Any:
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped_view

    # -----------------------------------------------------------------------
    # 5. HTML Templates (Auto-Escaped by Jinja2)
    # -----------------------------------------------------------------------

    BASE_HTML = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{{ title }}</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 440px; margin: 3rem auto; padding: 0 1rem; }
            label, input, button { display: block; width: 100%; margin-bottom: 0.75rem; box-sizing: border-box; }
            input, button { padding: 0.5rem; }
            .flash { padding: 0.6rem; background: #fee2e2; border: 1px solid #ef4444; margin-bottom: 1rem; }
        </style>
    </head>
    <body>
        <h1>{{ title }}</h1>
        {% with messages = get_flashed_messages() %}
            {% for msg in messages %}
                <div class="flash">{{ msg }}</div>
            {% endfor %}
        {% endwith %}
        {{ content | safe }}
    </body>
    </html>
    """

    def render_page(title: str, body_template: str, **context: Any) -> str:
        # Render body first so all user variables are strictly auto-escaped before wrapping
        rendered_body = render_template_string(body_template, **context)
        return render_template_string(BASE_HTML, title=title, content=rendered_body)

    # -----------------------------------------------------------------------
    # 6. Authentication & Session Routes
    # -----------------------------------------------------------------------

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            error = validate_credentials(username, password)
            if error:
                flash(error)
                return redirect(url_for("register"))

            password_hash = ph.hash(password)
            now = datetime.now(timezone.utc).isoformat()
            db = get_db()

            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, password_hash, now),
                )
                db.commit()
            except sqlite3.IntegrityError:
                flash("Username is already taken.")
                return redirect(url_for("register"))

            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        return render_page(
            "Register",
            """
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Username <input type="text" name="username" required minlength="3" maxlength="32"></label>
                <label>Password <input type="password" name="password" required minlength="12" maxlength="128"></label>
                <button type="submit">Create Account</button>
            </form>
            <p><a href="{{ url_for('login') }}">Already have an account? Log in</a></p>
            """,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            db = get_db()
            user = db.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            # Verify password even when user is not found to prevent timing-based user enumeration
            target_hash = user["password_hash"] if user else DUMMY_HASH
            try:
                ph.verify(target_hash, password)
                password_valid = user is not None
            except VerifyMismatchError:
                password_valid = False

            if not password_valid:
                flash("Invalid username or password.")
                return redirect(url_for("login"))

            # Rehash automatically if Argon2 parameters are upgraded in the future
            if ph.check_needs_rehash(user["password_hash"]):
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (ph.hash(password), user["id"]),
                )

            # Prevent Session Fixation: wipe pre-auth session & issue fresh cryptographic token
            session.clear()
            session.permanent = True
            new_session_token = secrets.token_urlsafe(32)
            expires_at = (
                datetime.now(timezone.utc) + app.config["PERMANENT_SESSION_LIFETIME"]
            ).isoformat()

            db.execute(
                "INSERT INTO active_sessions (session_token, user_id, expires_at) VALUES (?, ?, ?)",
                (new_session_token, user["id"], expires_at),
            )
            db.commit()

            session["user_id"] = user["id"]
            session["session_token"] = new_session_token
            session["_csrf_token"] = secrets.token_urlsafe(32)

            return redirect(url_for("dashboard"))

        return render_page(
            "Log In",
            """
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Username <input type="text" name="username" required></label>
                <label>Password <input type="password" name="password" required></label>
                <button type="submit">Log In</button>
            </form>
            <p><a href="{{ url_for('register') }}">Need an account? Register</a></p>
            """,
        )

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_page(
            "Dashboard",
            """
            <p>Signed in as <strong>{{ username }}</strong>.</p>
            <form method="post" action="{{ url_for('logout') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button type="submit">Log Out</button>
            </form>
            """,
            username=g.user["username"],
        )

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session_token = session.get("session_token")
        if session_token:
            db = get_db()
            db.execute("DELETE FROM active_sessions WHERE session_token = ?", (session_token,))
            db.commit()
        session.clear()
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    application = create_app()
    # Never enable debug=True in production; use a WSGI server (e.g., gunicorn)
    application.run(host="127.0.0.1", port=5000, debug=False)