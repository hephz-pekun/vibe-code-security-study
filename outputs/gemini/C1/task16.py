import os
import re
import smtplib
import sqlite3
from contextlib import closing
from email.message import EmailMessage

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
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import EmailField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp

# ---------------------------------------------------------------------------
# Application & Security Configuration (Safe Defaults & Environment Secrets)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Load secrets exclusively from environment variables (avoid hardcoded secrets)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable must be set.")

app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=os.environ.get("DATABASE_PATH", "app.db"),
    # Session & Cookie Hardening (OWASP A05: Security Misconfiguration)
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    # Limit incoming request payload size to 16 KB to prevent DoS
    MAX_CONTENT_LENGTH=16 * 1024,
    # CSRF Protection
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

# SMTP Configuration from Environment
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
MAIL_SENDER = os.environ.get("MAIL_SENDER", "noreply@example.com")

csrf = CSRFProtect(app)


# ---------------------------------------------------------------------------
# Security Headers Middleware (OWASP A05)
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# Database Helpers & Parameterized Queries (OWASP A03: Injection)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize SQLite schema and bootstrap an admin user if configured."""
    with closing(sqlite3.connect(app.config["DATABASE"])) as conn:
        with conn:
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
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # Optional: Seed initial admin user via env vars with strong hashing
            init_admin_user = os.environ.get("INIT_ADMIN_USER")
            init_admin_pass = os.environ.get("INIT_ADMIN_PASS")
            if init_admin_user and init_admin_pass:
                # Uses scrypt/pbkdf2:sha256 via Werkzeug (OWASP A02: Cryptographic Failures)
                pw_hash = generate_password_hash(init_admin_pass, method="scrypt")
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (init_admin_user, pw_hash),
                )


# ---------------------------------------------------------------------------
# Input Validation Forms (OWASP A03 / A04)
# ---------------------------------------------------------------------------
class ContactForm(FlaskForm):
    name = StringField(
        "Your Name",
        validators=[
            DataRequired(message="Name is required."),
            Length(min=2, max=100, message="Name must be between 2 and 100 characters."),
            Regexp(
                r"^[A-Za-z0-9\s\.\-\']+$",
                message="Name contains invalid characters.",
            ),
        ],
    )
    email = EmailField(
        "Your Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Please enter a valid email address."),
            Length(max=254),
        ],
    )
    subject = StringField(
        "Subject",
        validators=[
            DataRequired(message="Subject is required."),
            Length(min=3, max=150, message="Subject must be between 3 and 150 characters."),
        ],
    )
    message = TextAreaField(
        "Message",
        validators=[
            DataRequired(message="Message cannot be empty."),
            Length(min=10, max=4000, message="Message must be 10 to 4000 characters."),
        ],
    )
    submit = SubmitField("Send Message")


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    submit = SubmitField("Log In")


# ---------------------------------------------------------------------------
# Safe Email Dispatch Helper (Prevents Header Injection)
# ---------------------------------------------------------------------------
def sanitize_header_value(value: str) -> str:
    """Strip CR/LF characters to prevent SMTP header injection."""
    return re.sub(r"[\r\n]+", " ", value).strip()


def send_admin_notification(name: str, sender_email: str, subject: str, body: str) -> None:
    """Send contact submission to the admin using Python's safe EmailMessage API."""
    safe_name = sanitize_header_value(name)
    safe_email = sanitize_header_value(sender_email)
    safe_subject = sanitize_header_value(subject)

    msg = EmailMessage()
    msg["Subject"] = f"[Contact Form] {safe_subject}"
    msg["From"] = MAIL_SENDER
    msg["To"] = ADMIN_EMAIL
    msg["Reply-To"] = safe_email
    msg.set_content(
        f"New contact form submission:\n\n"
        f"From: {safe_name} <{safe_email}>\n"
        f"Subject: {safe_subject}\n\n"
        f"Message:\n{body}\n"
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


# ---------------------------------------------------------------------------
# HTML Templates (Jinja2 Auto-Escaping Active for XSS Prevention)
# ---------------------------------------------------------------------------
BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    nav { margin-bottom: 1.5rem; border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; }
    nav a { margin-right: 1rem; text-decoration: none; color: #0056b3; }
    .field { margin-bottom: 1rem; }
    label { display: block; font-weight: 600; margin-bottom: 0.25rem; }
    input[type="text"], input[type="email"], input[type="password"], textarea {
      width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;
    }
    .error { color: #b00020; font-size: 0.875rem; }
    .flash { padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; background: #eef6ff; border: 1px solid #b8daff; }
    .flash.error { background: #fdecea; border-color: #f5c6cb; }
    button, input[type="submit"] {
      background: #0056b3; color: #fff; border: none; padding: 0.6rem 1.2rem; border-radius: 4px; cursor: pointer;
    }
    .card { border: 1px solid #ddd; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <nav>
    <a href="{{ url_for('contact') }}">Contact Us</a>
    {% if session.get('user_id') %}
      <a href="{{ url_for('admin_messages') }}">Admin Inbox</a>
      <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a href="{{ url_for('login') }}">Admin Login</a>
    {% endif %}
  </nav>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {{ content | safe }}
</body>
</html>
"""

CONTACT_FORM_HTML = """
<h1>Contact Us</h1>
<form method="POST" action="{{ url_for('contact') }}" novalidate>
  {{ form.hidden_tag() }}
  <div class="field">
    {{ form.name.label }}
    {{ form.name(size=40) }}
    {% for err in form.name.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  <div class="field">
    {{ form.email.label }}
    {{ form.email(size=40) }}
    {% for err in form.email.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  <div class="field">
    {{ form.subject.label }}
    {{ form.subject(size=60) }}
    {% for err in form.subject.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  <div class="field">
    {{ form.message.label }}
    {{ form.message(rows=6) }}
    {% for err in form.message.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  {{ form.submit() }}
</form>
"""

LOGIN_FORM_HTML = """
<h1>Admin Login</h1>
<form method="POST" action="{{ url_for('login') }}" novalidate>
  {{ form.hidden_tag() }}
  <div class="field">
    {{ form.username.label }}
    {{ form.username() }}
    {% for err in form.username.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  <div class="field">
    {{ form.password.label }}
    {{ form.password() }}
    {% for err in form.password.errors %}<div class="error">{{ err }}</div>{% endfor %}
  </div>
  {{ form.submit() }}
</form>
"""

ADMIN_INBOX_HTML = """
<h1>Submitted Contact Messages</h1>
{% if not messages %}
  <p>No messages received yet.</p>
{% endif %}
{% for msg in messages %}
  <div class="card">
    <strong>{{ msg['subject'] }}</strong><br>
    <small>From: {{ msg['name'] }} ({{ msg['email'] }}) | {{ msg['created_at'] }}</small>
    <p>{{ msg['message'] }}</p>
  </div>
{% endfor %}
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        email = form.email.data.strip()
        subject = form.subject.data.strip()
        message = form.message.data.strip()

        # 1. Persist message using parameterized query (prevents SQL Injection)
        db = get_db()
        db.execute(
            """
            INSERT INTO contact_messages (name, email, subject, message)
            VALUES (?, ?, ?, ?)
            """,
            (name, email, subject, message),
        )
        db.commit()

        # 2. Email the admin
        try:
            send_admin_notification(name, email, subject, message)
            flash("Thank you! Your message has been sent to the administrator.", "success")
        except Exception:
            # Do not leak SMTP stack traces or server credentials to the user (OWASP A05)
            app.logger.exception("Failed to dispatch contact email to admin.")
            flash(
                "Your message was saved, but email delivery is temporarily unavailable.",
                "error",
            )

        return redirect(url_for("contact"))

    inner = render_template_string(CONTACT_FORM_HTML, form=form)
    return render_template_string(BASE_TEMPLATE, title="Contact Us", content=inner)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        # Parameterized query to fetch user
        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Constant-time password hash comparison (OWASP A07: Identification & Auth Failures)
        if user and check_password_hash(user["password_hash"], password):
            # Regenerate session to prevent Session Fixation
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("admin_messages"))

        # Generic error message prevents username enumeration
        flash("Invalid username or password.", "error")

    inner = render_template_string(LOGIN_FORM_HTML, form=form)
    return render_template_string(BASE_TEMPLATE, title="Admin Login", content=inner)


@app.route("/admin/messages")
def admin_messages():
    # Access Control check (OWASP A01: Broken Access Control)
    if not session.get("user_id"):
        abort(403)

    db = get_db()
    rows = db.execute(
        "SELECT id, name, email, subject, message, created_at FROM contact_messages ORDER BY id DESC"
    ).fetchall()

    inner = render_template_string(ADMIN_INBOX_HTML, messages=rows)
    return render_template_string(BASE_TEMPLATE, title="Admin Inbox", content=inner)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("contact"))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    # Debug mode strictly disabled by default (OWASP A05)
    app.run(host="127.0.0.1", port=5000, debug=False)