import csv
import io
import os
import re
import sqlite3
from contextlib import closing

from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    url_for,
)
from argon2 import PasswordHasher
from werkzeug.utils import secure_filename

###############################################################################
# Security Configuration
###############################################################################

# Generate and set:
# export FLASK_SECRET_KEY="<long-random-secret>"
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be configured."
    )

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_EXTENSIONS = {"csv"}

DATABASE = "users.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # use HTTPS in production
    SESSION_COOKIE_SAMESITE="Lax",
)

ph = PasswordHasher()

###############################################################################
# Database
###############################################################################


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


###############################################################################
# Validation
###############################################################################

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


def allowed_file(filename):
    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


def validate_username(username):
    return bool(USERNAME_PATTERN.fullmatch(username))


def validate_email(email):
    return bool(EMAIL_PATTERN.fullmatch(email))


def validate_password(password):
    # Example minimum policy
    if len(password) < 12:
        return False

    return True


###############################################################################
# User Import Logic
###############################################################################


def insert_user(username, email, password_hash):
    """
    Uses parameterized queries to prevent SQL injection.
    """
    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        conn.commit()


def process_csv(file_storage):
    filename = secure_filename(file_storage.filename)

    if not filename:
        raise ValueError("Missing filename.")

    if not allowed_file(filename):
        raise ValueError("Only CSV files are allowed.")

    try:
        content = file_storage.stream.read().decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("CSV must be UTF-8 encoded.")

    csv_reader = csv.DictReader(io.StringIO(content))

    required_headers = {"username", "email", "password"}

    if not csv_reader.fieldnames:
        raise ValueError("CSV is missing headers.")

    received_headers = {h.strip() for h in csv_reader.fieldnames}

    if received_headers != required_headers:
        raise ValueError(
            "CSV headers must be exactly: "
            "username,email,password"
        )

    imported = 0
    errors = []

    for line_number, row in enumerate(csv_reader, start=2):
        try:
            username = row["username"].strip()
            email = row["email"].strip().lower()
            password = row["password"]

            if not validate_username(username):
                raise ValueError("Invalid username.")

            if not validate_email(email):
                raise ValueError("Invalid email.")

            if not validate_password(password):
                raise ValueError(
                    "Password must be at least 12 characters."
                )

            password_hash = ph.hash(password)

            try:
                insert_user(username, email, password_hash)
                imported += 1

            except sqlite3.IntegrityError:
                raise ValueError(
                    "Username or email already exists."
                )

        except Exception as exc:
            errors.append(
                f"Line {line_number}: {str(exc)}"
            )

    return imported, errors


###############################################################################
# Admin Upload Route
###############################################################################

HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>CSV User Import</title>
</head>
<body>
    <h2>Admin User Import</h2>

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for msg in messages %}
            <li>{{ msg }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    <form method="POST" enctype="multipart/form-data">
        <label for="file">CSV File:</label>
        <input
            type="file"
            id="file"
            name="file"
            accept=".csv"
            required
        >
        <button type="submit">Import</button>
    </form>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def upload_users():
    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file:
            flash("No file provided.")
            return redirect(url_for("upload_users"))

        try:
            imported, errors = process_csv(uploaded_file)

            flash(f"Successfully imported {imported} users.")

            for error in errors:
                flash(error)

        except Exception:
            # Avoid exposing implementation details
            flash(
                "Unable to process file. "
                "Verify the CSV format and try again."
            )

        return redirect(url_for("upload_users"))

    return render_template_string(HTML)


###############################################################################
# Startup
###############################################################################

initialize_database()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )