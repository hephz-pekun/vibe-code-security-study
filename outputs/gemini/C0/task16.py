import os
import re
import smtplib
from email.message import EmailMessage
from flask import Flask, flash, redirect, render_template_string, request, url_for

app = Flask(__name__)

# Required for session management (flash messages)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-to-a-random-secret-key")

# SMTP & Admin Configuration (set these via environment variables in production)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "your-email@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "your-app-password")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f4f6f8;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 480px;
        }
        h2 { margin-top: 0; color: #333; }
        .form-group { margin-bottom: 16px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; color: #444; }
        input, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 15px;
        }
        input:focus, textarea:focus {
            border-color: #0066cc;
            outline: none;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { background-color: #0052a3; }
        .alert {
            padding: 12px;
            margin-bottom: 16px;
            border-radius: 4px;
            font-size: 14px;
        }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Contact Us</h2>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('contact') }}">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" id="name" name="name" value="{{ form_data.get('name', '') }}" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" value="{{ form_data.get('email', '') }}" required>
            </div>
            <div class="form-group">
                <label for="subject">Subject</label>
                <input type="text" id="subject" name="subject" value="{{ form_data.get('subject', '') }}" required>
            </div>
            <div class="form-group">
                <label for="message">Message</label>
                <textarea id="message" name="message" rows="5" required>{{ form_data.get('message', '') }}</textarea>
            </div>
            <button type="submit">Send Message</button>
        </form>
    </div>
</body>
</html>
"""


def send_admin_email(name: str, sender_email: str, subject: str, message_body: str) -> None:
    """Constructs and sends an email to the administrator via SMTP."""
    msg = EmailMessage()
    msg["Subject"] = f"[Contact Form] {subject}"
    msg["From"] = SMTP_USERNAME
    msg["To"] = ADMIN_EMAIL
    # Setting Reply-To allows the admin to hit 'Reply' and respond directly to the user
    msg["Reply-To"] = sender_email

    body = (
        f"You have received a new message from your website contact form.\n\n"
        f"Name: {name}\n"
        f"Email: {sender_email}\n"
        f"Subject: {subject}\n\n"
        f"Message:\n"
        f"{'-' * 40}\n"
        f"{message_body}\n"
    )
    msg.set_content(body)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("contact"))


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form_data = {}

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        form_data = {"name": name, "email": email, "subject": subject, "message": message}

        # Server-side validation
        if not all([name, email, subject, message]):
            flash("All fields are required.", "error")
        elif not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
        else:
            try:
                send_admin_email(name, email, subject, message)
                flash("Thank you! Your message has been sent to the admin.", "success")
                return redirect(url_for("contact"))
            except Exception as e:
                app.logger.error(f"Failed to send email: {e}")
                flash("Sorry, there was an error sending your message. Please try again later.", "error")

    return render_template_string(HTML_TEMPLATE, form_data=form_data)


if __name__ == "__main__":
    app.run(debug=True)