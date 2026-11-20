import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, render_template_string, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# Django password validation
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

# --------------------------------------------------
# Configuration
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Explicitly configure the external hostname instead of
# trusting the Host header when generating URLs.
app.config["SERVER_NAME"] = os.getenv("SERVER_NAME", "localhost:5000")

db = SQLAlchemy(app)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

# --------------------------------------------------
# Database Model
# --------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        """
        Validate password before hashing and saving.
        """
        validate_password(password)
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


# --------------------------------------------------
# Email Utility
# --------------------------------------------------


def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = MAIL_USERNAME
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)


# --------------------------------------------------
# Password Reset Utilities
# --------------------------------------------------


def generate_reset_token(email):
    return serializer.dumps(email, salt="password-reset")


def verify_reset_token(token, max_age=3600):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=max_age,
        )
        return email
    except (SignatureExpired, BadSignature):
        return None


# --------------------------------------------------
# Routes
# --------------------------------------------------


@app.route("/")
def home():
    return render_template_string(
        """
        <h2>Flask Password Reset Demo</h2>
        <ul>
            <li><a href="{{ url_for('register') }}">Register</a></li>
            <li><a href="{{ url_for('login') }}">Login</a></li>
            <li><a href="{{ url_for('forgot_password') }}">Forgot Password</a></li>
        </ul>
        """
    )


# ---------------------------
# Register
# ---------------------------


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        password = request.form["password"]

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("User already exists")
            return redirect(url_for("register"))

        user = User(email=email)

        try:
            user.set_password(password)
        except ValidationError as exc:
            flash("; ".join(exc.messages))
            return redirect(url_for("register"))

        db.session.add(user)
        db.session.commit()

        flash("Registration successful")
        return redirect(url_for("login"))

    return render_template_string(
        """
        <h2>Register</h2>

        {% with msgs = get_flashed_messages() %}
          {% for msg in msgs %}
            <p style="color:green">{{ msg }}</p>
          {% endfor %}
        {% endwith %}

        <form method="POST">
            <input
                type="email"
                name="email"
                placeholder="Email"
                required
            ><br><br>

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            ><br><br>

            <button type="submit">Register</button>
        </form>
        """
    )


# ---------------------------
# Login
# ---------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.verify_password(password):
            # Render via template engine rather than returning
            # formatted HTML strings containing user data.
            return render_template_string(
                """
                <h3>Welcome {{ email }}</h3>
                <p>Login successful.</p>
                """,
                email=email,
            )

        flash("Invalid credentials")
        return redirect(url_for("login"))

    return render_template_string(
        """
        <h2>Login</h2>

        {% with msgs = get_flashed_messages() %}
          {% for msg in msgs %}
            <p style="color:red">{{ msg }}</p>
          {% endfor %}
        {% endwith %}

        <form method="POST">
            <input
                type="email"
                name="email"
                placeholder="Email"
                required
            ><br><br>

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            ><br><br>

            <button type="submit">Login</button>
        </form>
        """
    )


# ---------------------------
# Forgot Password
# ---------------------------


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].lower().strip()

        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(email)

            # Generate external URL using configured SERVER_NAME
            # instead of the incoming Host header.
            reset_link = url_for(
                "reset_password",
                token=token,
                _external=True,
                _scheme="https",
            )

            body = f"""
Hello,

You requested a password reset.

Click the link below to reset your password:

{reset_link}

This link expires in 1 hour.

If you did not request this reset, ignore this email.
"""

            send_email(
                to_email=email,
                subject="Password Reset Request",
                body=body,
            )

        flash(
            "If an account exists for that email, a reset link has been sent."
        )

        return redirect(url_for("forgot_password"))

    return render_template_string(
        """
        <h2>Forgot Password</h2>

        {% with msgs = get_flashed_messages() %}
          {% for msg in msgs %}
            <p style="color:green">{{ msg }}</p>
          {% endfor %}
        {% endwith %}

        <form method="POST">
            <input
                type="email"
                name="email"
                placeholder="Email address"
                required
            ><br><br>

            <button type="submit">
                Send Reset Link
            </button>
        </form>
        """
    )


# ---------------------------
# Reset Password
# ---------------------------


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    email = verify_reset_token(token)

    if not email:
        return render_template_string(
            """
            <h3>Invalid or expired token.</h3>
            """
        )

    user = User.query.filter_by(email=email).first()

    if not user:
        return render_template_string(
            """
            <h3>User not found.</h3>
            """
        )

    if request.method == "POST":
        new_password = request.form["password"]

        try:
            user.set_password(new_password)
        except ValidationError as exc:
            flash("; ".join(exc.messages))
            return redirect(url_for("reset_password", token=token))

        db.session.commit()

        flash("Password successfully reset")
        return redirect(url_for("login"))

    return render_template_string(
        """
        <h2>Reset Password</h2>

        {% with msgs = get_flashed_messages() %}
          {% for msg in msgs %}
            <p style="color:red">{{ msg }}</p>
          {% endfor %}
        {% endwith %}

        <form method="POST">

            <input
                type="password"
                name="password"
                placeholder="New Password"
                required
            ><br><br>

            <button type="submit">
                Reset Password
            </button>

        </form>
        """
    )


# --------------------------------------------------
# Main
# --------------------------------------------------

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    # Never enable debug mode in production.
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )