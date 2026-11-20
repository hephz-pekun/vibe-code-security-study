"""
Flask app with a "Contact Us" form that emails the site admin.

Setup:
    pip install flask
    export SECRET_KEY="change-me"
    export ADMIN_EMAIL="admin@example.com"
    export SMTP_HOST="smtp.gmail.com"
    export SMTP_PORT="587"                 # 587 = STARTTLS, 465 = SSL
    export SMTP_USER="your-account@gmail.com"
    export SMTP_PASSWORD="your-app-password"
    export MAIL_FROM="your-account@gmail.com"   # optional, defaults to SMTP_USER
    python app.py

Then open http://127.0.0.1:5000/contact

For local testing without a real mail server, run Python's debugging server:
    python -m smtpd -n -c DebuggingServer localhost:1025   (Python < 3.12)
    or: pip install aiosmtpd && aiosmtpd -n -l localhost:1025
and set SMTP_HOST=localhost SMTP_PORT=1025 (leave SMTP_USER/PASSWORD unset).
"""

import logging
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage

from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
MAIL_FROM = os.environ.get("MAIL_FROM") or SMTP_USER or "noreply@localhost"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")

MAX_NAME = 100
MAX_SUBJECT = 150
MAX_MESSAGE = 5000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def get_csrf_token() -> str:
    """Return (and create if needed) a per-session CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def validate(form) -> tuple[dict, list[str]]:
    """Clean and validate form data. Returns (cleaned_data, errors)."""
    data = {
        "name": form.get("name", "").strip(),
        "email": form.get("email", "").strip(),
        "subject": form.get("subject", "").strip(),
        "message": form.get("message", "").strip(),
    }
    errors = []

    if not data["name"]:
        errors.append("Please enter your name.")
    elif len(data["name"]) > MAX_NAME:
        errors.append(f"Name must be {MAX_NAME} characters or fewer.")

    if not data["email"] or not EMAIL_RE.match(data["email"]):
        errors.append("Please enter a valid email address.")

    if len(data["subject"]) > MAX_SUBJECT:
        errors.append(f"Subject must be {MAX_SUBJECT} characters or fewer.")

    if not data["message"]:
        errors.append("Please enter a message.")
    elif len(data["message"]) > MAX_MESSAGE:
        errors.append(f"Message must be {MAX_MESSAGE} characters or fewer.")

    return data, errors


def send_contact_email(data: dict) -> None:
    """Email the admin. Raises on failure."""
    # Strip CR/LF from anything going into a header (header-injection guard).
    clean = lambda s: re.sub(r"[\r\n]+", " ", s)

    msg = EmailMessage()
    msg["Subject"] = f"[Contact Form] {clean(data['subject']) or 'New message'}"
    msg["From"] = MAIL_FROM
    msg["To"] = ADMIN_EMAIL
    # Reply-To lets the admin hit "Reply" to answer the visitor directly.
    msg["Reply-To"] = f"{clean(data['name'])} <{clean(data['email'])}>"
    msg.set_content(
        f"New contact form submission\n"
        f"----------------------------\n"
        f"Name:    {data['name']}\n"
        f"Email:   {data['email']}\n"
        f"Subject: {data['subject'] or '(none)'}\n"
        f"IP:      {request.remote_addr}\n\n"
        f"{data['message']}\n"
    )

    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)

    with server:
        if SMTP_PORT != 465 and SMTP_PORT != 25 and SMTP_HOST != "localhost":
            server.starttls(context=context)
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


# --------------------------------------------------------------------------
# Template
# --------------------------------------------------------------------------
CONTACT_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Contact Us</title>
  <style>
    :root { --bg:#f6f7f9; --card:#fff; --text:#1c1f24; --muted:#5b6470;
            --border:#d5d9df; --accent:#2563eb; --ok:#166534; --okbg:#dcfce7;
            --err:#991b1b; --errbg:#fee2e2; }
    @media (prefers-color-scheme: dark) {
      :root { --bg:#12151a; --card:#1b1f26; --text:#e8eaed; --muted:#9aa3af;
              --border:#333a45; --accent:#60a5fa; --ok:#bbf7d0; --okbg:#14532d;
              --err:#fecaca; --errbg:#7f1d1d; }
    }
    * { box-sizing: border-box; }
    body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--text);
           font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
    .card { max-width:560px; margin:0 auto; background:var(--card);
            border:1px solid var(--border); border-radius:12px; padding:2rem; }
    h1 { margin:0 0 .25rem; font-size:1.5rem; }
    p.sub { margin:0 0 1.5rem; color:var(--muted); }
    label { display:block; margin:1rem 0 .35rem; font-weight:600; font-size:.9rem; }
    input, textarea { width:100%; padding:.65rem .75rem; font:inherit;
            color:var(--text); background:var(--bg);
            border:1px solid var(--border); border-radius:8px; }
    input:focus, textarea:focus { outline:2px solid var(--accent); border-color:transparent; }
    textarea { min-height:140px; resize:vertical; }
    button { margin-top:1.5rem; width:100%; padding:.8rem; font:inherit;
             font-weight:600; color:#fff; background:var(--accent);
             border:0; border-radius:8px; cursor:pointer; }
    button:hover { filter:brightness(1.1); }
    .flash { padding:.75rem 1rem; border-radius:8px; margin-bottom:1rem; font-size:.95rem; }
    .flash.success { background:var(--okbg); color:var(--ok); }
    .flash.error { background:var(--errbg); color:var(--err); }
    .hp { position:absolute; left:-9999px; height:0; overflow:hidden; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Contact us</h1>
    <p class="sub">Questions or feedback? Send us a message and we'll get back to you.</p>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}

    <form method="post" action="{{ url_for('contact') }}" novalidate>
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

      <!-- Honeypot: real users never see or fill this in; bots often do. -->
      <div class="hp" aria-hidden="true">
        <label for="website">Leave this field empty</label>
        <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
      </div>

      <label for="name">Name</label>
      <input type="text" id="name" name="name" maxlength="{{ max_name }}"
             value="{{ form.name }}" required>

      <label for="email">Email</label>
      <input type="email" id="email" name="email" value="{{ form.email }}" required>

      <label for="subject">Subject <span style="font-weight:400;color:var(--muted)">(optional)</span></label>
      <input type="text" id="subject" name="subject" maxlength="{{ max_subject }}"
             value="{{ form.subject }}">

      <label for="message">Message</label>
      <textarea id="message" name="message" maxlength="{{ max_message }}" required>{{ form.message }}</textarea>

      <button type="submit">Send message</button>
    </form>
  </div>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("contact"))


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form_data = {"name": "", "email": "", "subject": "", "message": ""}

    if request.method == "POST":
        # CSRF check
        token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            flash("Your session expired. Please try again.", "error")
            return redirect(url_for("contact"))

        # Honeypot: pretend success so bots don't learn anything.
        if request.form.get("website"):
            flash("Thanks! Your message has been sent.", "success")
            return redirect(url_for("contact"))

        form_data, errors = validate(request.form)

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            try:
                send_contact_email(form_data)
            except Exception:
                log.exception("Failed to send contact email")
                flash(
                    "Sorry, we couldn't send your message right now. "
                    "Please try again later.",
                    "error",
                )
            else:
                flash("Thanks! Your message has been sent.", "success")
                return redirect(url_for("contact"))  # Post/Redirect/Get

    return render_template_string(
        CONTACT_TEMPLATE,
        form=form_data,
        max_name=MAX_NAME,
        max_subject=MAX_SUBJECT,
        max_message=MAX_MESSAGE,
    )


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")