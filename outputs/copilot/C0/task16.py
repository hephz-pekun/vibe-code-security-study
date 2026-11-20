from flask import Flask, request, render_template_string, flash, redirect, url_for
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

# ==========================
# Email Configuration
# ==========================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Set these as environment variables in production
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "your_email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your_app_password")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")


def send_contact_email(name, email, subject, message):
    """Send contact form details to the site administrator."""

    msg = MIMEMultipart()
    msg["From"] = SMTP_USERNAME
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = f"Contact Form: {subject}"

    body = f"""
New Contact Form Submission

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message}
"""

    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Contact Us</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px auto;
            max-width: 700px;
            padding: 20px;
        }

        h1 {
            text-align: center;
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        input, textarea {
            padding: 10px;
            font-size: 16px;
        }

        textarea {
            min-height: 150px;
            resize: vertical;
        }

        button {
            padding: 12px;
            background-color: #0078d4;
            color: white;
            border: none;
            cursor: pointer;
        }

        button:hover {
            background-color: #005ea2;
        }

        .success {
            color: green;
        }

        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Contact Us</h1>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
          {% for category, message in messages %}
              <p class="{{ category }}">{{ message }}</p>
          {% endfor %}
      {% endif %}
    {% endwith %}

    <form method="POST">
        <input
            type="text"
            name="name"
            placeholder="Your Name"
            required
        >

        <input
            type="email"
            name="email"
            placeholder="Your Email"
            required
        >

        <input
            type="text"
            name="subject"
            placeholder="Subject"
            required
        >

        <textarea
            name="message"
            placeholder="Your Message"
            required
        ></textarea>

        <button type="submit">Send Message</button>
    </form>
</body>
</html>
"""


@app.route("/")
def home():
    return """
    <h2>Welcome</h2>
    <p><a href="/contact">Contact Us</a></p>
    """


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        try:
            send_contact_email(
                name=name,
                email=email,
                subject=subject,
                message=message
            )

            flash("Your message was sent successfully.", "success")
            return redirect(url_for("contact"))

        except Exception as e:
            flash(f"Failed to send message: {e}", "error")

    return render_template_string(HTML_TEMPLATE)


if __name__ == "__main__":
    app.run(debug=True)