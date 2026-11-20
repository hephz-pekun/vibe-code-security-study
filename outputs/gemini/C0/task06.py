import os
from functools import wraps
from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Mail Configuration (Defaults to printing emails to console if SMTP is not set)
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "localhost")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 8025))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "false").lower() == "true"
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get(
    "MAIL_DEFAULT_SENDER", "noreply@example.com"
)
# Set to False in production once real SMTP credentials are configured
app.config["MAIL_SUPPRESS_SEND"] = (
    os.environ.get("MAIL_SUPPRESS_SEND", "true").lower() == "true"
)

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

RESET_SALT = "password-reset-salt"
TOKEN_MAX_AGE_SECONDS = 1800  # 30 minutes


# ---------------------------------------------------------------------------
# Database Model
# ---------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self) -> str:
        # Including the last 8 chars of password_hash ensures the token
        # becomes invalid as soon as the password is successfully changed.
        payload = {"user_id": self.id, "pw_sig": self.password_hash[-8:]}
        return serializer.dumps(payload, salt=RESET_SALT)

    @staticmethod
    def verify_reset_token(token: str):
        try:
            data = serializer.loads(
                token, salt=RESET_SALT, max_age=TOKEN_MAX_AGE_SECONDS
            )
        except (SignatureExpired, BadSignature):
            return None

        user = db.session.get(User, data.get("user_id"))
        if not user or user.password_hash[-8:] != data.get("pw_sig"):
            return None
        return user


# ---------------------------------------------------------------------------
# Email Helper
# ---------------------------------------------------------------------------
def send_reset_email(user: User):
    token = user.generate_reset_token()
    reset_url = url_for("reset_password", token=token, _external=True)

    msg = Message(
        subject="Password Reset Request",
        recipients=[user.email],
        body=(
            f"To reset your password, visit the following link (valid for 30 minutes):\n\n"
            f"{reset_url}\n\n"
            f"If you did not make this request, simply ignore this email."
        ),
    )

    if app.config["MAIL_SUPPRESS_SEND"]:
        print("\n" + "=" * 60)
        print(f"[DEV MODE EMAIL] To: {user.email}")
        print(f"Reset Link: {reset_url}")
        print("=" * 60 + "\n")
    else:
        mail.send(msg)


# ---------------------------------------------------------------------------
# HTML Templates (Embedded for single-file portability)
# ---------------------------------------------------------------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Flask Auth & Password Reset</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 420px; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
    form { display: flex; flex-direction: column; gap: 0.75rem; }
    input, button { padding: 0.6rem; font-size: 1rem; }
    button { background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    .flash { padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; background: #f3f4f6; border-left: 4px solid #2563eb; }
    .links { margin-top: 1rem; font-size: 0.9rem; display: flex; gap: 1rem; }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      {% for msg in messages %}
        <div class="flash">{{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {{ content | safe }}
</body>
</html>
"""


def render_page(body_html: str, **context):
    rendered_body = render_template_string(body_html, **context)
    return render_template_string(BASE_HTML, content=rendered_body)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])

    if user:
        return render_page(
            """
            <h2>Dashboard</h2>
            <p>Logged in as <strong>{{ email }}</strong></p>
            <div class="links">
              <a href="{{ url_for('logout') }}">Log out</a>
            </div>
            """,
            email=user.email,
        )
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.")
        else:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created! Please log in.")
            return redirect(url_for("login"))

    return render_page(
        """
        <h2>Create Account</h2>
        <form method="post">
          <input type="email" name="email" placeholder="Email" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Register</button>
        </form>
        <div class="links">
          <a href="{{ url_for('login') }}">Already have an account? Login</a>
        </div>
        """
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        flash("Invalid email or password.")

    return render_page(
        """
        <h2>Login</h2>
        <form method="post">
          <input type="email" name="email" placeholder="Email" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Log In</button>
        </form>
        <div class="links">
          <a href="{{ url_for('forgot_password') }}">Forgot password?</a>
          <a href="{{ url_for('register') }}">Register</a>
        </div>
        """
    )


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            send_reset_email(user)

        # Always show the exact same message to prevent account enumeration
        flash(
            "If an account exists for that email, a password reset link has been sent."
        )
        return redirect(url_for("login"))

    return render_page(
        """
        <h2>Forgot Password</h2>
        <p>Enter your email address and we'll send you a link to reset your password.</p>
        <form method="post">
          <input type="email" name="email" placeholder="Email" required>
          <button type="submit">Send Reset Link</button>
        </form>
        <div class="links">
          <a href="{{ url_for('login') }}">Back to Login</a>
        </div>
        """
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash("The password reset link is invalid or has expired.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
        elif password != confirm:
            flash("Passwords do not match.")
        else:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been updated! You can now log in.")
            return redirect(url_for("login"))

    return render_page(
        """
        <h2>Reset Your Password</h2>
        <form method="post">
          <input type="password" name="password" placeholder="New password (min 8 chars)" required>
          <input type="password" name="confirm_password" placeholder="Confirm new password" required>
          <button type="submit">Reset Password</button>
        </form>
        """
    )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)