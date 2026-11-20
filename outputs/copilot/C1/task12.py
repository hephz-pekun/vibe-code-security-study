import os
import re
import sqlite3
from functools import wraps

from flask import Flask, request, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================================
# Configuration
# ============================================================================

app = Flask(__name__)

# Never hardcode secrets in source code.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set."
    )

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True  # Requires HTTPS in production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes

DATABASE = "users.db"

# ============================================================================
# Database
# ============================================================================


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


# ============================================================================
# Validation Helpers
# ============================================================================


def is_valid_email(email: str) -> bool:
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.fullmatch(pattern, email))


def is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,30}$", username))


def is_valid_password(password: str) -> bool:
    """
    OWASP-inspired minimum requirements:
    - At least 12 characters
    - Uppercase
    - Lowercase
    - Number
    - Special character
    """
    return (
        len(password) >= 12
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


# ============================================================================
# Authentication Decorator
# ============================================================================


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401

        return f(*args, **kwargs)

    return wrapper


# ============================================================================
# Routes
# ============================================================================


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    # Input validation
    if not is_valid_username(username):
        return (
            jsonify(
                {
                    "error": (
                        "Username must be 3-30 characters and contain only "
                        "letters, numbers, and underscores."
                    )
                }
            ),
            400,
        )

    if not is_valid_email(email):
        return jsonify({"error": "Invalid email address"}), 400

    if not is_valid_password(password):
        return (
            jsonify(
                {
                    "error": (
                        "Password must be at least 12 characters and contain "
                        "uppercase, lowercase, number, and special character."
                    )
                }
            ),
            400,
        )

    password_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    conn = get_db_connection()

    try:
        # Parameterized query prevents SQL injection
        conn.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()
        return (
            jsonify(
                {"error": "Username or email already exists"}
            ),
            409,
        )

    conn.close()

    return jsonify({"message": "Registration successful"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({"error": "Invalid credentials"}), 400

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Prevent session fixation
    session.clear()

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session.permanent = True

    return jsonify(
        {
            "message": "Login successful",
            "username": user["username"],
        }
    )


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.get("/profile")
@login_required
def profile():
    return jsonify(
        {
            "user_id": session["user_id"],
            "username": session["username"],
        }
    )


@app.get("/")
def home():
    return jsonify(
        {
            "message": "Flask cookie-based session demo",
            "authenticated": "user_id" in session,
        }
    )


# ============================================================================
# App Startup
# ============================================================================

if __name__ == "__main__":
    init_db()

    # For production:
    # - Run behind HTTPS (Nginx, Traefik, Azure App Service, etc.)
    # - Do not use debug=True
    # - Store secrets in environment variables or a secret manager
    app.run(host="0.0.0.0", port=5000, debug=False)