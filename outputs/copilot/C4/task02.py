import os
import re
import sqlite3
from datetime import timedelta

from flask import (
    Flask,
    request,
    redirect,
    render_template_string,
    session,
    flash,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Secure Flask Configuration
# =========================

app = Flask(__name__)

# Do NOT hardcode secrets.
# Set an environment variable:
# Linux/macOS:
#   export FLASK_SECRET_KEY="your-random-secret"
#
# Windows PowerShell:
#   $env:FLASK_SECRET_KEY="your-random-secret"
#
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is required."
    )

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Set True when using HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

DATABASE = "users.db"

# =========================
# Database Functions
# =========================

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
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.commit()
    db.close()


# =========================
# Input Validation
# =========================

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def validate_registration(username, email, password):
    errors = []

    username = username.strip()
    email = email.strip().lower()

    if not USERNAME_REGEX.match(username):
        errors.append(
            "Username must be 3-30 characters and contain only letters, numbers, or underscores."
        )

    if not EMAIL_REGEX.match(email):
        errors.append("Invalid email address.")

    # OWASP-aligned password requirements
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain a number.")

    return errors


# =========================
# HTML Templates
# =========================

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h2>Create Account</h2>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}

    <form method="POST" autocomplete="off">
        <label>Username:</label><br>
        <input type="text" name="username" maxlength="30" required><br><br>

        <label>Email:</label><br>
        <input type="email" name="email" maxlength="255" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" minlength="12" required><br><br>

        <button type="submit">Register</button>
    </form>

    <p><a href="/login">Login</a></p>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}

    <form method="POST" autocomplete="off">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <button type="submit">Login</button>
    </form>

    <p><a href="/register">Register</a></p>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h2>Welcome, {{ username|e }}</h2>

    <p>You are logged in.</p>

    <form method="POST" action="/logout">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
"""


# =========================
# Routes
# =========================

@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        validation_errors = validate_registration(
            username,
            email,
            password,
        )

        if validation_errors:
            for error in validation_errors:
                flash(error)
            return render_template_string(REGISTER_TEMPLATE)

        db = get_db()

        # Parameterized queries prevent SQL injection
        existing_user = db.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?
            """,
            (username, email),
        ).fetchone()

        if existing_user:
            flash("Username or email already exists.")
            return render_template_string(REGISTER_TEMPLATE)

        # Werkzeug uses a strong password hashing algorithm (PBKDF2)
        password_hash = generate_password_hash(password)

        db.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                email,
                password_hash,
            ),
        )

        db.commit()

        flash("Registration successful. Please log in.")
        return redirect("/login")

    return render_template_string(REGISTER_TEMPLATE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            """
            SELECT id,
                   username,
                   password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        # Generic error message avoids username enumeration
        if not user or not check_password_hash(
            user["password_hash"],
            password,
        ):
            flash("Invalid username or password.")
            return render_template_string(LOGIN_TEMPLATE)

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = True

        return redirect("/dashboard")

    return render_template_string(LOGIN_TEMPLATE)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session["username"],
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect("/login")


# =========================
# Application Entry Point
# =========================

if __name__ == "__main__":
    init_db()

    # Use debug=False in production
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )