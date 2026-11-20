import os
import re
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    flash,
    render_template_string,
    g
)
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# Configuration
# =============================================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set."
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set True when using HTTPS
    PERMANENT_SESSION_LIFETIME=1800,
)

DATABASE = "comments.db"

# =============================================================================
# Database
# =============================================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    db.commit()
    db.close()

# =============================================================================
# Security Helpers
# =============================================================================

def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    return (
        form_token
        and session_token
        and secrets.compare_digest(form_token, session_token)
    )


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def validate_username(username):
    if not username:
        return False

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return False

    return True


def validate_password(password):
    return len(password) >= 12


def validate_comment(comment):
    if not comment:
        return False

    if len(comment) > 500:
        return False

    return True

# =============================================================================
# Security Headers
# =============================================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response

# =============================================================================
# Templates
# =============================================================================

PAGE_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Secure Comment Board</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>Secure Comment Board</h1>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    {% if user %}
        <p>
            Logged in as <strong>{{ user }}</strong>
            |
            <a href="{{ url_for('logout') }}">Logout</a>
        </p>

        <form method="post" action="{{ url_for('add_comment') }}">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <textarea
                name="comment"
                rows="4"
                cols="60"
                maxlength="500"
                required></textarea>

            <br><br>

            <button type="submit">Post Comment</button>
        </form>
    {% else %}
        <p>
            <a href="{{ url_for('login') }}">Login</a>
            |
            <a href="{{ url_for('register') }}">Register</a>
        </p>
    {% endif %}

    <hr>

    <h2>Comments</h2>

    {% for comment in comments %}
        <div>
            <strong>{{ comment.username }}</strong>
            ({{ comment.created_at }})
            <br>
            {{ comment.comment }}
        </div>
        <hr>
    {% endfor %}
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!doctype html>
<html>
<body>
<h1>Register</h1>

<form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

    <label>Username:</label><br>
    <input name="username" required maxlength="30"><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Register</button>
</form>

<p><a href="{{ url_for('index') }}">Home</a></p>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<body>
<h1>Login</h1>

<form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

    <label>Username:</label><br>
    <input name="username" required><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Login</button>
</form>

<p><a href="{{ url_for('index') }}">Home</a></p>
</body>
</html>
"""

# =============================================================================
# Routes
# =============================================================================

@app.route("/")
def index():
    db = get_db()

    comments = db.execute("""
        SELECT comments.comment,
               comments.created_at,
               users.username
        FROM comments
        JOIN users
          ON comments.user_id = users.id
        ORDER BY comments.id DESC
    """).fetchall()

    return render_template_string(
        PAGE_TEMPLATE,
        comments=comments,
        user=session.get("username"),
        csrf_token=generate_csrf_token()
    )


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not validate_csrf():
            return "CSRF validation failed", 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_username(username):
            flash(
                "Username must be 3-30 characters and contain only "
                "letters, numbers, and underscores."
            )
            return redirect(url_for("register"))

        if not validate_password(password):
            flash(
                "Password must be at least 12 characters long."
            )
            return redirect(url_for("register"))

        password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16
        )

        try:
            db = get_db()

            db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash)
            )

            db.commit()

            flash("Registration successful.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

    return render_template_string(
        REGISTER_TEMPLATE,
        csrf_token=generate_csrf_token()
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if not validate_csrf():
            return "CSRF validation failed", 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful.")
            return redirect(url_for("index"))

        flash("Invalid username or password.")
        return redirect(url_for("login"))

    return render_template_string(
        LOGIN_TEMPLATE,
        csrf_token=generate_csrf_token()
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))


@app.route("/comment", methods=["POST"])
@login_required
def add_comment():

    if not validate_csrf():
        return "CSRF validation failed", 400

    comment = request.form.get("comment", "").strip()

    if not validate_comment(comment):
        flash(
            "Comment is required and must not exceed 500 characters."
        )
        return redirect(url_for("index"))

    db = get_db()

    db.execute(
        """
        INSERT INTO comments (user_id, comment)
        VALUES (?, ?)
        """,
        (session["user_id"], comment)
    )

    db.commit()

    flash("Comment posted.")
    return redirect(url_for("index"))

# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )