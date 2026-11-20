import os
import secrets
import sqlite3
from pathlib import Path

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    flash,
    session,
    abort,
    send_from_directory,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms.csrf.session import SessionCSRF

# =====================================================
# Configuration
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "app.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"

UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set."
    )

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# Secure cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# =====================================================
# Database
# =====================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            profile_picture TEXT
        )
    """)

    conn.commit()
    conn.close()


# =====================================================
# Security Helpers
# =====================================================

def allowed_extension(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def validate_image_signature(file_stream):
    """
    Basic file signature validation.
    Checks magic bytes for common image formats.
    """

    header = file_stream.read(16)
    file_stream.seek(0)

    signatures = [
        b"\xff\xd8\xff",          # JPG
        b"\x89PNG\r\n\x1a\n",     # PNG
        b"GIF87a",                # GIF
        b"GIF89a",                # GIF
        b"RIFF",                  # WEBP starts with RIFF
    ]

    return any(header.startswith(sig) for sig in signatures)


def get_user(user_id):
    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    conn.close()
    return user


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    return get_user(user_id)


def login_required():
    if not current_user():
        abort(401)


# =====================================================
# Forms
# =====================================================

class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=50),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )

    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# =====================================================
# Routes
# =====================================================

@app.route("/")
def index():
    user = current_user()

    return render_template_string("""
    <h1>Secure Profile Upload Demo</h1>

    {% with messages = get_flashed_messages() %}
      {% for msg in messages %}
        <p><b>{{ msg }}</b></p>
      {% endfor %}
    {% endwith %}

    {% if user %}
        <p>Logged in as {{ user['username'] }}</p>

        {% if user['profile_picture'] %}
            <img
                src="{{ url_for('uploaded_file', filename=user['profile_picture']) }}"
                width="200"
                alt="Profile Picture">
        {% endif %}

        <form
            method="POST"
            action="/upload"
            enctype="multipart/form-data">

            <input
                type="file"
                name="profile_picture"
                accept=".jpg,.jpeg,.png,.gif,.webp"
                required>

            <button type="submit">
                Upload Profile Picture
            </button>
        </form>

        <p><a href="/logout">Logout</a></p>

    {% else %}
        <p><a href="/register">Register</a></p>
        <p><a href="/login">Login</a></p>
    {% endif %}
    """, user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16
        )

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash),
            )

            conn.commit()

        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

        finally:
            conn.close()

        flash("Registration successful.")
        return redirect(url_for("login"))

    return render_template_string("""
    <h2>Register</h2>

    <form method="POST">
        {{ form.hidden_tag() }}

        {{ form.username.label }}
        {{ form.username }}
        <br><br>

        {{ form.password.label }}
        {{ form.password }}
        <br><br>

        {{ form.submit }}
    </form>
    """, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (form.username.data.strip(),),
        ).fetchone()

        conn.close()

        if (
            user
            and check_password_hash(
                user["password_hash"],
                form.password.data
            )
        ):
            session.clear()
            session["user_id"] = user["id"]

            flash("Login successful.")
            return redirect(url_for("index"))

        flash("Invalid credentials.")

    return render_template_string("""
    <h2>Login</h2>

    <form method="POST">
        {{ form.hidden_tag() }}

        {{ form.username.label }}
        {{ form.username }}
        <br><br>

        {{ form.password.label }}
        {{ form.password }}
        <br><br>

        {{ form.submit }}
    </form>
    """, form=form)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
def upload():
    login_required()

    file = request.files.get("profile_picture")

    if not file:
        flash("No file uploaded.")
        return redirect(url_for("index"))

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    if not allowed_extension(file.filename):
        flash("Invalid file type.")
        return redirect(url_for("index"))

    if not validate_image_signature(file.stream):
        flash("File content does not match an image.")
        return redirect(url_for("index"))

    original_name = secure_filename(file.filename)

    extension = original_name.rsplit(".", 1)[1].lower()

    random_filename = (
        f"{secrets.token_hex(16)}.{extension}"
    )

    save_path = UPLOAD_FOLDER / random_filename

    file.save(save_path)

    user = current_user()

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET profile_picture = ?
        WHERE id = ?
        """,
        (random_filename, user["id"]),
    )

    conn.commit()
    conn.close()

    flash("Profile picture uploaded successfully.")

    return redirect(url_for("index"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )


# =====================================================
# Error Handlers
# =====================================================

@app.errorhandler(413)
def request_entity_too_large(_):
    return (
        "Uploaded file exceeds maximum size (5 MB).",
        413,
    )


@app.errorhandler(401)
def unauthorized(_):
    return "Authentication required.", 401


# =====================================================
# Startup
# =====================================================

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )