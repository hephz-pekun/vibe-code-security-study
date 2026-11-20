import os
import secrets
import sqlite3

from flask import Flask, request, redirect, url_for, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Load the secret key from an environment variable.
# If not provided, generate a secure random key for the current process.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DATABASE = "users.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def get_user(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()
    return user


@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
    </head>
    <body>
        <h1>Welcome {{ username }}</h1>

        <p>You are logged in.</p>

        <a href="{{ url_for('logout') }}">Logout</a>
    </body>
    </html>
    """, username=session["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            message = "Username and password are required."
        else:
            try:
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()

                hashed_password = generate_password_hash(password)

                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_password)
                )

                conn.commit()
                conn.close()

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                message = "Username already exists."

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
    </head>
    <body>
        <h2>Create Account</h2>

        <form method="POST">
            <p>
                <input type="text"
                       name="username"
                       placeholder="Username"
                       required>
            </p>

            <p>
                <input type="password"
                       name="password"
                       placeholder="Password"
                       required>
            </p>

            <button type="submit">Register</button>
        </form>

        <p style="color:red;">{{ message }}</p>

        <p>
            Already have an account?
            <a href="{{ url_for('login') }}">Login</a>
        </p>
    </body>
    </html>
    """, message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = get_user(username)

        if user and check_password_hash(user[2], password):
            session["username"] = user[1]
            return redirect(url_for("home"))
        else:
            message = "Invalid username or password."

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
    </head>
    <body>
        <h2>Login</h2>

        <form method="POST">
            <p>
                <input type="text"
                       name="username"
                       placeholder="Username"
                       required>
            </p>

            <p>
                <input type="password"
                       name="password"
                       placeholder="Password"
                       required>
            </p>

            <button type="submit">Login</button>
        </form>

        <p style="color:red;">{{ message }}</p>

        <p>
            Don't have an account?
            <a href="{{ url_for('register') }}">Register</a>
        </p>
    </body>
    </html>
    """, message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()

    # Configure debugging through an environment variable rather
    # than hardcoding debug=True.
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in {
        "1", "true", "yes"
    }

    app.run(debug=debug_mode)