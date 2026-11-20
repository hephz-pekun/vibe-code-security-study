import hashlib
import os
import re
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from functools import wraps
from typing import Optional

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (No Hardcoded Secrets)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Require a cryptographically strong secret key from environment in production
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("FLASK_SECRET_KEY environment variable must be set in production.")
    SECRET_KEY = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=os.environ.get("DATABASE_PATH", "app.db"),
    # Secure cookie defaults
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    # Password reset settings
    RESET_TOKEN_TTL_SECONDS=int(os.environ.get("RESET_TOKEN_TTL_SECONDS", 900)),  # 15 minutes
    APP_BASE_URL=os.environ.get("APP_BASE_URL", "https://example.com").rstrip("/"),
    # SMTP settings
    SMTP_HOST=os.environ.get("SMTP_HOST", "localhost"),
    SMTP_PORT=int(os.environ.get("SMTP_PORT", 587)),
    SMTP_USER=os.environ.get("SMTP_USER", ""),
    SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
    SMTP_FROM=os.environ.get("SMTP_FROM", "no-reply@example.com"),
    SMTP_USE_TLS=os.environ.get("SMTP_USE_TLS", "true").lower() == "true",
    # Limit incoming payload size (16 KB) to prevent DoS
    MAX_CONTENT_LENGTH=16 * 1024,
)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Simple in-memory rate limiter (use Redis in multi-worker production setups)
_RATE_LIMIT_STORE: dict[str, list[float]] = {}


# ---------------------------------------------------------------------------
# Security Middleware & Rate Limiting
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


def rate_limit(max_requests: int, window_seconds: int):
    """Per-IP sliding window rate limiter to mitigate brute-force and email flooding."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr or "unknown"
            key = f"{fn.__name__}:{client_ip}"
            now = time.time()
            timestamps = [t for t in _RATE_LIMIT_STORE.get(key, []) if now - t < window_seconds]

            if len(timestamps) >= max_requests:
                return jsonify({"error": "Too many requests. Please try again later."}), 429

            timestamps.append(now)
            _RATE_LIMIT_STORE[key] = timestamps
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Database Layer (Parameterized Queries Only)
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash);
        """
    )
    db.commit()


# ---------------------------------------------------------------------------
# Validation & Cryptographic Helpers
# ---------------------------------------------------------------------------
def validate_email(email: Optional[str]) -> Optional[str]:
    if not isinstance(email, str):
        return None
    normalized = email.strip().lower()
    if len(normalized) > 254 or not EMAIL_REGEX.match(normalized):
        return None
    return normalized


def validate_password(password: Optional[str]) -> Optional[str]:
    """Enforce NIST SP 800-63B style length and basic complexity checks."""
    if not isinstance(password, str):
        return "Password must be a string."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must not exceed {MAX_PASSWORD_LENGTH} characters."
    if not any(c.islower() for c in password):
        return "Password must include at least one lowercase letter."
    if not any(c.isupper() for c in password):
        return "Password must include at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must include at least one digit."
    return None


def hash_password_strong(password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256 (600,000 iterations)."""
    return generate_password_hash(password, method="pbkdf2:sha256:600000", salt_length=16)


def hash_reset_token(raw_token: str) -> str:
    """Store only a SHA-256 digest of high-entropy reset tokens in the database."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def send_reset_email(recipient_email: str, raw_token: str) -> None:
    """Send password reset link over TLS-encrypted SMTP."""
    reset_url = f"{app.config['APP_BASE_URL']}/reset-password?token={raw_token}"

    msg = EmailMessage()
    msg["Subject"] = "Password Reset Request"
    msg["From"] = app.config["SMTP_FROM"]
    msg["To"] = recipient_email
    msg.set_content(
        f"You requested a password reset.\n\n"
        f"Use the link below within {app.config['RESET_TOKEN_TTL_SECONDS'] // 60} minutes "
        f"to set a new password:\n{reset_url}\n\n"
        f"If you did not request this, you can safely ignore this email."
    )

    # In local dev without an SMTP server, log to stdout instead of failing
    if not app.config["SMTP_USER"] and app.config["SMTP_HOST"] == "localhost":
        app.logger.info("[DEV EMAIL] To: %s | Reset URL: %s", recipient_email, reset_url)
        return

    with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"], timeout=10) as server:
        if app.config["SMTP_USE_TLS"]:
            server.starttls()
        if app.config["SMTP_USER"] and app.config["SMTP_PASSWORD"]:
            server.login(app.config["SMTP_USER"], app.config["SMTP_PASSWORD"])
        server.send_message(msg)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.post("/register")
@rate_limit(max_requests=5, window_seconds=300)
def register():
    data = request.get_json(silent=True) or {}
    email = validate_email(data.get("email"))
    password = data.get("password")

    if not email:
        return jsonify({"error": "Invalid email address."}), 400

    pw_error = validate_password(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, hash_password_strong(password), int(time.time())),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Avoid leaking whether an account already exists if desired, or return generic error
        return jsonify({"error": "Unable to register with provided details."}), 400

    return jsonify({"message": "Account created successfully."}), 201


@app.post("/forgot-password")
@rate_limit(max_requests=5, window_seconds=300)
def forgot_password():
    """
    Step 1: Request a password reset email.
    Always returns HTTP 200 with an identical message to prevent user enumeration.
    """
    data = request.get_json(silent=True) or {}
    email = validate_email(data.get("email"))

    generic_response = (
        jsonify({"message": "If an account with that email exists, a reset link has been sent."}),
        200,
    )

    if not email:
        return generic_response

    db = get_db()
    user = db.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()

    if user:
        now = int(time.time())
        raw_token = secrets.token_urlsafe(32)  # 256 bits of CSPRNG entropy
        token_digest = hash_reset_token(raw_token)
        expires_at = now + app.config["RESET_TOKEN_TTL_SECONDS"]

        # Invalidate any prior unused tokens for this user before issuing a new one
        db.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
            (user["id"],),
        )
        db.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (user["id"], token_digest, expires_at, now),
        )
        db.commit()

        try:
            send_reset_email(user["email"], raw_token)
        except Exception:
            app.logger.exception("Failed to send password reset email.")

    return generic_response


@app.post("/reset-password")
@rate_limit(max_requests=10, window_seconds=300)
def reset_password():
    """
    Step 2: Verify single-use token and update the user's password.
    """
    data = request.get_json(silent=True) or {}
    raw_token = data.get("token")
    new_password = data.get("new_password")

    if not isinstance(raw_token, str) or not (32 <= len(raw_token) <= 128):
        return jsonify({"error": "Invalid or expired reset token."}), 400

    pw_error = validate_password(new_password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    token_digest = hash_reset_token(raw_token)
    now = int(time.time())
    db = get_db()

    record = db.execute(
        """
        SELECT id, user_id, token_hash, expires_at, used
        FROM password_reset_tokens
        WHERE token_hash = ?
        """,
        (token_digest,),
    ).fetchone()

    # Constant-time comparison on the stored digest + expiration & single-use checks
    if (
        not record
        or not secrets.compare_digest(record["token_hash"], token_digest)
        or record["used"] != 0
        or record["expires_at"] < now
    ):
        return jsonify({"error": "Invalid or expired reset token."}), 400

    new_password_hash = hash_password_strong(new_password)

    # Atomically mark token as used and update password
    try:
        db.execute("BEGIN IMMEDIATE")
        updated = db.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ? AND used = 0",
            (record["id"],),
        )
        if updated.rowcount != 1:
            db.rollback()
            return jsonify({"error": "Invalid or expired reset token."}), 400

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, record["user_id"]),
        )
        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Error completing password reset.")
        return jsonify({"error": "Could not complete password reset."}), 500

    return jsonify({"message": "Password has been reset successfully."}), 200


@app.post("/login")
@rate_limit(max_requests=10, window_seconds=300)
def login():
    """Verification endpoint to test logging in with the reset password."""
    data = request.get_json(silent=True) or {}
    email = validate_email(data.get("email"))
    password = data.get("password")

    # Dummy hash used when user does not exist to mitigate timing-based user enumeration
    dummy_hash = "pbkdf2:sha256:600000$0000000000000000$0000000000000000000000000000000000000000000000000000000000000000"

    if not email or not isinstance(password, str):
        check_password_hash(dummy_hash, "invalid")
        return jsonify({"error": "Invalid credentials."}), 401

    db = get_db()
    user = db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()

    stored_hash = user["password_hash"] if user else dummy_hash
    if not check_password_hash(stored_hash, password) or not user:
        return jsonify({"error": "Invalid credentials."}), 401

    return jsonify({"message": "Authenticated successfully."}), 200


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
with app.app_context():
    init_db()

if __name__ == "__main__":
    # Debug mode explicitly disabled by default
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )