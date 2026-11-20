import os
import sqlite3
from functools import wraps

from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature

# ============================================================
# Configuration
# ============================================================

DATABASE = "notes.db"

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable must be set."
    )

TOKEN_EXPIRATION_SECONDS = 3600 * 24

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

serializer = URLSafeTimedSerializer(SECRET_KEY)

# ============================================================
# Database Helpers
# ============================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    db.commit()
    db.close()


# ============================================================
# Security Headers
# ============================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# ============================================================
# Validation
# ============================================================

def validate_username(username):
    if not isinstance(username, str):
        return False

    username = username.strip()

    if len(username) < 3 or len(username) > 50:
        return False

    return True


def validate_password(password):
    if not isinstance(password, str):
        return False

    return len(password) >= 12


def validate_note(title, content):
    if not isinstance(title, str) or not isinstance(content, str):
        return False

    if not title.strip():
        return False

    if len(title) > 200:
        return False

    if len(content) > 10000:
        return False

    return True


# ============================================================
# Authentication
# ============================================================

def create_token(user_id):
    return serializer.dumps({"user_id": user_id})


def get_user_from_token(token):
    try:
        data = serializer.loads(
            token,
            max_age=TOKEN_EXPIRATION_SECONDS
        )
        return data["user_id"]
    except BadSignature:
        return None


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(" ", 1)[1].strip()

        user_id = get_user_from_token(token)

        if user_id is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        request.user_id = user_id

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# User Registration
# ============================================================

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400

    if not validate_password(password):
        return jsonify({
            "error": "Password must be at least 12 characters"
        }), 400

    password_hash = generate_password_hash(password)

    db = get_db()

    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username.strip(), password_hash)
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"message": "User created"}), 201


# ============================================================
# Login
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    db = get_db()

    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(
        user["password_hash"],
        password
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user["id"])

    return jsonify({"token": token})


# ============================================================
# Create Note
# ============================================================

@app.route("/notes", methods=["POST"])
@auth_required
def create_note():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    title = data.get("title", "")
    content = data.get("content", "")

    if not validate_note(title, content):
        return jsonify({"error": "Invalid note"}), 400

    db = get_db()

    cursor = db.execute(
        """
        INSERT INTO notes (user_id, title, content)
        VALUES (?, ?, ?)
        """,
        (request.user_id, title.strip(), content)
    )

    db.commit()

    return jsonify({
        "id": cursor.lastrowid,
        "message": "Note created"
    }), 201


# ============================================================
# Read All Notes
# ============================================================

@app.route("/notes", methods=["GET"])
@auth_required
def get_notes():
    db = get_db()

    rows = db.execute(
        """
        SELECT id, title, content, created_at, updated_at
        FROM notes
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (request.user_id,)
    ).fetchall()

    notes = [dict(row) for row in rows]

    return jsonify(notes)


# ============================================================
# Read One Note
# ============================================================

@app.route("/notes/<int:note_id>", methods=["GET"])
@auth_required
def get_note(note_id):
    db = get_db()

    note = db.execute(
        """
        SELECT id, title, content, created_at, updated_at
        FROM notes
        WHERE id = ? AND user_id = ?
        """,
        (note_id, request.user_id)
    ).fetchone()

    if not note:
        return jsonify({"error": "Note not found"}), 404

    return jsonify(dict(note))


# ============================================================
# Update Note
# ============================================================

@app.route("/notes/<int:note_id>", methods=["PUT"])
@auth_required
def update_note(note_id):
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    title = data.get("title", "")
    content = data.get("content", "")

    if not validate_note(title, content):
        return jsonify({"error": "Invalid note"}), 400

    db = get_db()

    existing = db.execute(
        """
        SELECT id
        FROM notes
        WHERE id = ? AND user_id = ?
        """,
        (note_id, request.user_id)
    ).fetchone()

    if not existing:
        return jsonify({"error": "Note not found"}), 404

    db.execute(
        """
        UPDATE notes
        SET title = ?,
            content = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
        """,
        (
            title.strip(),
            content,
            note_id,
            request.user_id
        )
    )

    db.commit()

    return jsonify({"message": "Note updated"})


# ============================================================
# Delete Note
# ============================================================

@app.route("/notes/<int:note_id>", methods=["DELETE"])
@auth_required
def delete_note(note_id):
    db = get_db()

    cursor = db.execute(
        """
        DELETE FROM notes
        WHERE id = ?
          AND user_id = ?
        """,
        (note_id, request.user_id)
    )

    db.commit()

    if cursor.rowcount == 0:
        return jsonify({"error": "Note not found"}), 404

    return jsonify({"message": "Note deleted"})


# ============================================================
# Health Check
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )