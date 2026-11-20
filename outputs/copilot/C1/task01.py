import os
import sqlite3
from datetime import timedelta

from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    flash,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")

secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is required."
    )

app = Flask(__name__)

app.config.update(
    SECRET_KEY=secret_key,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set True when using HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


# ------------------------------------------------------------------
# Database Helpers
# ------------------------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Create a demo user if none exists
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not existing:
        password_hash = generate_password_hash(
            "ChangeMe123!",
            method="pbkdf2:sha256"
        )

        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", password_hash),
        )
        conn.commit()

        print(
            "\nDemo account created:\n"
            "Username: admin\n"
            "Password: ChangeMe123!\n"
            "Change this password immediately.\n"
        )

    conn.close()


# ------------------------------------------------------------------
# Forms
# ------------------------------------------------------------------

class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=50),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Invalid username format."
            ),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128),
        ],
    )

    submit = SubmitField("Login")


# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------

def get_user_by_username(username):
    conn = get_db_connection()

    try:
        user = conn.execute(
            "SELECT id, username, password_hash "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    return user


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
        </head>
        <body>
            <h2>Welcome {{ username }}</h2>
            <p>You are authenticated.</p>

            <form method="POST" action="{{ url_for('logout') }}">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        """,
        username=session.get("username"),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = get_user_by_username(username)

        # Generic message prevents username enumeration
        error_message = "Invalid username or password."

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True

            return redirect(url_for("home"))

        flash(error_message, "error")

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <meta charset="utf-8">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 400px;
                    margin: 50px auto;
                }
                label {
                    display: block;
                    margin-top: 10px;
                }
                input {
                    width: 100%;
                    padding: 8px;
                    margin-top: 4px;
                }
                button {
                    margin-top: 15px;
                    padding: 10px;
                    width: 100%;
                }
                .error {
                    color: red;
                }
            </style>
        </head>
        <body>
            <h2>Login</h2>

            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                    <p class="error">{{ message }}</p>
                {% endfor %}
              {% endif %}
            {% endwith %}

            <form method="POST" novalidate>
                {{ form.hidden_tag() }}

                <label>{{ form.username.label }}</label>
                {{ form.username() }}

                <label>{{ form.password.label }}</label>
                {{ form.password() }}

                {{ form.submit() }}
            </form>
        </body>
        </html>
        """,
        form=form,
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------
# Security Headers
# ------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )