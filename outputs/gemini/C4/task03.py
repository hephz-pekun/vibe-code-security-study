import os
import uuid
import sqlite3
import secrets
from pathlib import Path
from functools import wraps
from PIL import Image, UnidentifiedImageError
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    send_from_directory,
    abort,
    flash,
    g,
)

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads" / "avatars"
DATABASE_PATH = BASE_DIR / "app.db"

ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_IMAGE_DIMENSIONS = (4096, 4096)
AVATAR_RESIZE_TO = (300, 300)

app = Flask(__name__)

# Avoid hardcoded secrets: read from environment or generate an ephemeral one for dev
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(32)
app.config["SECRET_KEY"] = secret_key

# Strict payload size limit (2 MB) to prevent Denial of Service (DoS)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Hardened session cookie flags
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Security Headers & CSRF Protection
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
    )
    return response


def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def validate_csrf():
    token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        abort(403, description="Invalid or missing CSRF token.")


# ---------------------------------------------------------------------------
# Database Helpers (Parameterized Queries Only)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar_filename TEXT
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Authentication Decorator
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# Image Validation & Sanitization
# ---------------------------------------------------------------------------
def process_and_save_avatar(file_storage) -> str:
    """
    Validates magic bytes via Pillow, enforces dimension caps, strips EXIF/metadata
    by re-encoding onto a fresh canvas, and saves with a non-guessable UUID filename.
    """
    try:
        # 1. Verify image integrity & prevent decompression bombs
        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_DIMENSIONS[0] * MAX_IMAGE_DIMENSIONS[1]
        img = Image.open(file_storage.stream)
        img.verify()

        # Re-open after verify() since verify() leaves the file pointer at the end
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)

        if img.format not in ALLOWED_FORMATS:
            raise ValueError("Unsupported image format. Allowed: JPEG, PNG, WEBP.")

        if img.width > MAX_IMAGE_DIMENSIONS[0] or img.height > MAX_IMAGE_DIMENSIONS[1]:
            raise ValueError("Image dimensions exceed 4096x4096 pixels.")

        # 2. Strip EXIF/embedded payloads by converting mode and re-encoding
        if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
            clean_img = img.convert("RGBA")
            ext = "png"
            save_format = "PNG"
        else:
            clean_img = img.convert("RGB")
            ext = "jpg"
            save_format = "JPEG"

        clean_img.thumbnail(AVATAR_RESIZE_TO, Image.Resampling.LANCZOS)

        # 3. Generate random UUID filename (never trust user-supplied filenames)
        safe_filename = f"{uuid.uuid4().hex}.{ext}"
        destination = (UPLOAD_FOLDER / safe_filename).resolve()

        # Ensure resolved path remains strictly inside UPLOAD_FOLDER
        if UPLOAD_FOLDER.resolve() not in destination.parents:
            raise ValueError("Invalid destination path.")

        clean_img.save(destination, format=save_format, quality=85, optimize=True)
        return safe_filename

    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        raise ValueError("Invalid or corrupted image file.") from exc


# ---------------------------------------------------------------------------
# HTML Templates (Auto-escaped by Jinja2)
# ---------------------------------------------------------------------------
LAYOUT_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Profile Avatar App</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 520px; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
    .flash { padding: 0.75rem; background: #f0f4f8; border-left: 4px solid #0066cc; margin-bottom: 1rem; }
    .card { border: 1px solid #ddd; padding: 1.5rem; border-radius: 8px; }
    label { display: block; margin-top: 1rem; font-weight: 600; }
    input[type="text"], input[type="password"], input[type="file"] { width: 100%; padding: 0.5rem; margin-top: 0.25rem; box-sizing: border-box; }
    button { margin-top: 1.25rem; padding: 0.6rem 1.2rem; cursor: pointer; }
    img.avatar { width: 150px; height: 150px; object-fit: cover; border-radius: 50%; border: 2px solid #ccc; display: block; margin: 1rem 0; }
    nav { margin-bottom: 1.5rem; display: flex; justify-content: space-between; }
  </style>
</head>
<body>
  <nav>
    <strong>SecureApp</strong>
    <div>
      {% if session.get('user_id') %}
        <a href="{{ url_for('profile') }}">Profile</a> |
        <a href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a href="{{ url_for('login') }}">Login</a> |
        <a href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </div>
  </nav>
  {% with messages = get_flashed_messages() %}
    {% for msg in messages %}
      <div class="flash">{{ msg }}</div>
    {% endfor %}
  {% endwith %}
  <div class="card">
    {{ content | safe }}
  </div>
</body>
</html>
"""


def render_page(inner_template: str, **context):
    rendered_inner = render_template_string(inner_template, **context)
    return render_template_string(LAYOUT_HTML, content=rendered_inner)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not (3 <= len(username) <= 32) or not username.isalnum():
            flash("Username must be 3-32 alphanumeric characters.")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Password must be at least 10 characters long.")
            return redirect(url_for("register"))

        # Strong password hashing using PBKDF2-SHA256 (or scrypt via Werkzeug)
        pw_hash = generate_password_hash(password, method="scrypt")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username is already taken.")
            return redirect(url_for("register"))

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_page(
        """
        <h2>Register</h2>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <label>Username</label>
          <input type="text" name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9]+">
          <label>Password (min 10 chars)</label>
          <input type="password" name="password" required minlength="10">
          <button type="submit">Create Account</button>
        </form>
        """
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Constant-time comparison via check_password_hash; generic error prevents user enumeration
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        # Regenerate session state on login to prevent session fixation
        session.clear()
        session["user_id"] = user["id"]
        generate_csrf_token()
        return redirect(url_for("profile"))

    return render_page(
        """
        <h2>Login</h2>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <label>Username</label>
          <input type="text" name="username" required>
          <label>Password</label>
          <input type="password" name="password" required>
          <button type="submit">Log In</button>
        </form>
        """
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user = db.execute(
        "SELECT id, username, avatar_filename FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        validate_csrf()

        if "avatar" not in request.files:
            flash("No file selected.")
            return redirect(url_for("profile"))

        file = request.files["avatar"]
        if not file or file.filename == "":
            flash("No file selected.")
            return redirect(url_for("profile"))

        try:
            new_filename = process_and_save_avatar(file)
        except ValueError as err:
            flash(str(err))
            return redirect(url_for("profile"))

        old_filename = user["avatar_filename"]

        # Update DB with parameterized query
        db.execute(
            "UPDATE users SET avatar_filename = ? WHERE id = ?",
            (new_filename, user["id"]),
        )
        db.commit()

        # Safely remove old avatar from disk to prevent storage exhaustion
        if old_filename:
            old_path = (UPLOAD_FOLDER / old_filename).resolve()
            if UPLOAD_FOLDER.resolve() in old_path.parents and old_path.is_file():
                old_path.unlink(missing_ok=True)

        flash("Profile picture updated.")
        return redirect(url_for("profile"))

    return render_page(
        """
        <h2>Welcome, {{ user['username'] }}</h2>
        {% if user['avatar_filename'] %}
          <img class="avatar" src="{{ url_for('serve_avatar', filename=user['avatar_filename']) }}" alt="Profile picture">
        {% else %}
          <p><em>No profile picture uploaded yet.</em></p>
        {% endif %}

        <form method="post" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <label>Upload New Profile Picture (JPEG, PNG, WEBP - Max 2MB)</label>
          <input type="file" name="avatar" accept="image/jpeg,image/png,image/webp" required>
          <button type="submit">Upload Picture</button>
        </form>
        """,
        user=user,
    )


@app.route("/avatars/<filename>")
@login_required
def serve_avatar(filename: str):
    # Strictly allow only 32-char hex UUID + .jpg/.png to eliminate path traversal
    stem, ext = os.path.splitext(filename)
    if ext not in {".jpg", ".png"} or len(stem) != 32 or not all(c in "0123456789abcdef" for c in stem):
        abort(404)

    response = send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, max-age=3600"
    return response


@app.errorhandler(413)
def file_too_large(error):
    flash("Uploaded file exceeds the 2 MB limit.")
    return redirect(url_for("profile"))


if __name__ == "__main__":
    init_db()
    # Never run with debug=True in production
    app.run(host="127.0.0.1", port=5000, debug=False)