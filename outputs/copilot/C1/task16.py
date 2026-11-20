import os
import re
import sqlite3
from datetime import datetime
from email.message import EmailMessage

from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import secrets


# ============================================================
# Configuration
# ============================================================

app = Flask(__name__)

# Never hardcode secrets. Set these as environment variables.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required.")

DATABASE = os.environ.get("DATABASE_PATH", "app.db")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"

if not ADMIN_EMAIL:
    raise RuntimeError("ADMIN_EMAIL environment variable is required.")


# ============================================================
# Database
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# Security Helpers
# ============================================================

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


def create_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf(token):
    stored = session.get("csrf_token")
    return stored and secrets.compare_digest(stored, token)


def sanitize_text(value, max_length):
    value = value.strip()

    if not value:
        return None

    if len(value) > max_length:
        return None

    return value


def is_valid_email(email):
    return bool(EMAIL_REGEX.match(email))


# ============================================================
# Email
# ============================================================

def send_contact_email(name, email, message):
    """
    Sends notification to the admin.

    SMTP credentials are loaded from environment variables.
    """

    if not all([
        SMTP_HOST,
        SMTP_USERNAME,
        SMTP_PASSWORD
    ]):
        app.logger.warning(
            "SMTP credentials not configured. "
            "Email notification skipped."
        )
        return

    email_msg = EmailMessage()
    email_msg["Subject"] = "New Contact Form Submission"
    email_msg["From"] = SMTP_USERNAME
    email_msg["To"] = ADMIN_EMAIL

    email_msg.set_content(
        f"""
New contact form submission

Name: {name}
Email: {email}

Message:
{message}
        """.strip()
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()

        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(email_msg)


# ============================================================
# Authentication Example
# Demonstrates strong password hashing.
# ============================================================

def create_user(username, password):
    """
    Example user creation using Werkzeug's PBKDF2 hashing.
    """

    password_hash = generate_password_hash(
        password,
        method="pbkdf2:sha256",
        salt_length=16
    )

    conn = get_db()

    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()


def verify_user(username, password):
    conn = get_db()

    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not row:
        return False

    return check_password_hash(row["password_hash"], password)


# ============================================================
# Routes
# ============================================================

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Contact Us</title>
</head>
<body>
    <h1>Contact Us</h1>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for msg in messages %}
          <li>{{ msg }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    <form method="POST">
        <input type="hidden"
               name="csrf_token"
               value="{{ csrf_token }}">

        <p>
            <label>Name</label><br>
            <input
                type="text"
                name="name"
                maxlength="100"
                required>
        </p>

        <p>
            <label>Email</label><br>
            <input
                type="email"
                name="email"
                maxlength="254"
                required>
        </p>

        <p>
            <label>Message</label><br>
            <textarea
                name="message"
                rows="6"
                cols="50"
                maxlength="5000"
                required></textarea>
        </p>

        <button type="submit">Send</button>
    </form>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def contact():

    if request.method == "POST":

        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf(csrf_token):
            flash("Invalid CSRF token.")
            return redirect(url_for("contact"))

        name = sanitize_text(
            request.form.get("name", ""),
            100
        )

        email = sanitize_text(
            request.form.get("email", ""),
            254
        )

        message = sanitize_text(
            request.form.get("message", ""),
            5000
        )

        if not all([name, email, message]):
            flash("All fields are required.")
            return redirect(url_for("contact"))

        if not is_valid_email(email):
            flash("Invalid email address.")
            return redirect(url_for("contact"))

        conn = get_db()

        # Parameterized query prevents SQL injection.
        conn.execute(
            """
            INSERT INTO contacts
            (name, email, message, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email,
                message,
                datetime.utcnow().isoformat()
            )
        )

        conn.commit()
        conn.close()

        try:
            send_contact_email(name, email, message)
        except Exception:
            app.logger.exception("Failed to send email.")

        flash("Your message has been submitted.")
        return redirect(url_for("contact"))

    csrf_token = create_csrf_token()
    return render_template_string(
        HTML_PAGE,
        csrf_token=csrf_token
    )


# ============================================================
# Secure Defaults
# ============================================================

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    return response


# ============================================================
# Startup
# ============================================================

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False  # Safe default
    )