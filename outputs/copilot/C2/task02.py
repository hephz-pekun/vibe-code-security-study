from flask import Flask, request, redirect, url_for, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets

app = Flask(__name__)

# Load the secret key from an environment variable.
# If not provided, generate a secure random key at startup.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DATABASE = "users.db"


# -----------------------------
# Database Setup
# -----------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# -----------------------------
# Templates
# -----------------------------
HOME_HTML = """
<!doctype html>
<html>
<head>
    <title>Flask Auth</title>
</head>
<body>
    <h2>Home</h2>

    {% if user %}
        <p>Logged in as <b>{{ user }}</b></p>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('register') }}">Register</a><br><br>
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
</body>
</html>
"""

REGISTER_HTML = """
<!doctype html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h2>Create Account</h2>

    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}

    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <button type="submit">Register</button>
    </form>

    <br>
    <a href="{{ url_for('login') }}">Already have an account?</a>
</body>
</html>
"""

LOGIN_HTML = """
<!doctype html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>

    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}

    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <button type="submit">Login</button>
    </form>

    <br>
    <a href="{{ url_for('register') }}">Create an account</a>
</body>
</html>
"""


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    return render_template_string(
        HOME_HTML,
        user=session.get("username")
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            password_hash = generate_password_hash(password)

            try:
                conn = get_db()
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                conn.close()

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                error = "Username already exists."

    return render_template_string(
        REGISTER_HTML,
        error=error
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            session["username"] = username
            return redirect(url_for("home"))
        else:
            error = "Invalid username or password."

    return render_template_string(
        LOGIN_HTML,
        error=error
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    # Configure debug mode via environment variable.
    # Example:
    #   FLASK_DEBUG=true python app.py
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in (
        "1",
        "true",
        "yes",
        "on"
    )

    app.run(debug=debug_mode)