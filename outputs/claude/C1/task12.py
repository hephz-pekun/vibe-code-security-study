"""
Secure cookie-based session system for Flask (single file).

Design
------
* Server-side sessions. The cookie holds only a random, opaque 256-bit token.
  The database stores SHA-256(token), so a DB leak does not yield usable
  session cookies. No signing key is needed, so there is no secret to hardcode.
* Cookie flags: HttpOnly, Secure, SameSite=Lax, __Host- prefix (when Secure),
  Path=/, no Domain attribute.
* Session fixation: every login destroys any old session and issues a new ID.
* Idle timeout + absolute timeout, enforced server-side.
* CSRF: JSON-only API + same-origin check on all state-changing requests, plus
  a per-session CSRF token (X-CSRF-Token header) for authenticated requests.
* Passwords: scrypt (via Werkzeug) with per-password random salt, constant-time
  verification, dummy hash for unknown users to blunt user enumeration timing.
* Brute force: per-account lockout after repeated failures.
* SQL: parameterized queries only.
* Input validation: strict types, lengths and character sets.
* Security headers on every response; generic error messages; no debug mode.

Configuration (environment variables, all optional)
---------------------------------------------------
APP_ENV              "production" (default) or "development" (allows HTTP cookies)
DATABASE_PATH        SQLite file path (default: ./app.db)
IDLE_TIMEOUT_SECS    default 1800   (30 min)
ABSOLUTE_TIMEOUT_SECS default 43200 (12 h)
MAX_FAILED_LOGINS    default 5
LOCKOUT_SECS         default 900
ALLOWED_ORIGINS      comma-separated extra origins permitted for unsafe requests,
                     e.g. "https://app.example.com" (needed behind some proxies)

Run (dev):   APP_ENV=development python secure_sessions.py
Run (prod):  gunicorn -w 4 'secure_sessions:create_app()'   # behind HTTPS
             (if behind a reverse proxy, wrap with werkzeug ProxyFix correctly)

Requires: Flask >= 2.3 (Werkzeug >= 2.3 for scrypt)
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from urllib.parse import urlparse

from flask import Flask, g, jsonify, make_response, request
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
        return value if value > 0 else default
    except ValueError:
        return default


IS_DEV = os.environ.get("APP_ENV", "production").lower() == "development"

DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")
IDLE_TIMEOUT = _int_env("IDLE_TIMEOUT_SECS", 30 * 60)
ABSOLUTE_TIMEOUT = _int_env("ABSOLUTE_TIMEOUT_SECS", 12 * 60 * 60)
MAX_FAILED_LOGINS = _int_env("MAX_FAILED_LOGINS", 5)
LOCKOUT_SECS = _int_env("LOCKOUT_SECS", 15 * 60)
ALLOWED_ORIGINS = {
    o.strip().rstrip("/")
    for o in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
}

COOKIE_SECURE = not IS_DEV  # safe default: Secure unless explicitly in dev
COOKIE_NAME = "__Host-session" if COOKIE_SECURE else "session"
LAST_SEEN_UPDATE_INTERVAL = 60  # seconds; limits DB writes

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128
HASH_METHOD = "scrypt"

# Hash checked when the username doesn't exist, so timing doesn't reveal it.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method=HASH_METHOD)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash    TEXT    PRIMARY KEY,          -- SHA-256 of the cookie token
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL              -- absolute expiry
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
"""

# --------------------------------------------------------------------------- #
# Database helpers (parameterized queries only)
# --------------------------------------------------------------------------- #

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def init_db() -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    try:  # best-effort: DB file readable only by the owner (POSIX)
        os.chmod(DATABASE_PATH, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Session primitives
# --------------------------------------------------------------------------- #

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int) -> tuple[str, str]:
    """Create a session; return (raw_cookie_token, csrf_token)."""
    token = secrets.token_urlsafe(32)       # 256 bits from the OS CSPRNG
    csrf = secrets.token_urlsafe(32)
    now = int(time.time())
    db = get_db()
    db.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (_hash_token(token), user_id, csrf, now, now, now + ABSOLUTE_TIMEOUT),
    )
    return token, csrf


def destroy_session_by_token(token: str | None) -> None:
    if token:
        get_db().execute("DELETE FROM sessions WHERE id_hash = ?", (_hash_token(token),))


def destroy_user_sessions(user_id: int, except_id_hash: str | None = None) -> None:
    db = get_db()
    if except_id_hash:
        db.execute(
            "DELETE FROM sessions WHERE user_id = ? AND id_hash != ?",
            (user_id, except_id_hash),
        )
    else:
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def purge_expired_sessions() -> None:
    now = int(time.time())
    get_db().execute(
        "DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?",
        (now, now - IDLE_TIMEOUT),
    )


def set_session_cookie(resp, token: str):
    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=ABSOLUTE_TIMEOUT,
        path="/",              # required for __Host- prefix
        secure=COOKIE_SECURE,
        httponly=True,         # not readable from JavaScript
        samesite="Lax",
        # no `domain` -> host-only cookie
    )
    return resp


def clear_session_cookie(resp):
    resp.set_cookie(
        COOKIE_NAME, "", expires=0, max_age=0, path="/",
        secure=COOKIE_SECURE, httponly=True, samesite="Lax",
    )
    return resp


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

class ValidationError(Exception):
    pass


def read_json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object.")
    return data


def validate_username(value) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        raise ValidationError(
            "Username must be 3-32 characters: letters, digits, '_', '.', '-'."
        )
    return value


def validate_new_password(value, username: str | None = None) -> str:
    if not isinstance(value, str):
        raise ValidationError("Password must be a string.")
    if not (PASSWORD_MIN <= len(value) <= PASSWORD_MAX):
        raise ValidationError(
            f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters long."
        )
    if "\x00" in value:
        raise ValidationError("Password contains invalid characters.")
    if username and username.lower() in value.lower():
        raise ValidationError("Password must not contain the username.")
    if len(set(value)) < 5:
        raise ValidationError("Password is too repetitive.")
    return value


def validate_login_password(value) -> str:
    # Only sanity-check on login (don't leak policy, avoid hashing huge inputs).
    if not isinstance(value, str) or not (1 <= len(value) <= PASSWORD_MAX) or "\x00" in value:
        raise ValidationError("Invalid credentials.")
    return value


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #

def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,      # small bodies only
        JSON_SORT_KEYS=False,
        PROPAGATE_EXCEPTIONS=False,
        DEBUG=False,
        TESTING=False,
    )
    # NOTE: Flask's built-in signed `session` is deliberately not used, so no
    # SECRET_KEY is required. If you add features needing one, load it from the
    # environment/secret manager (e.g. os.environ["SECRET_KEY"]); never hardcode.

    init_db()

    # ----------------------------- request hooks ---------------------------- #

    @app.before_request
    def load_session_and_enforce_csrf():
        g.user_id = None
        g.session_id_hash = None
        g.csrf_token = None
        g.raw_token = request.cookies.get(COOKIE_NAME)

        # Load session, if any.
        if g.raw_token and len(g.raw_token) <= 128:
            now = int(time.time())
            id_hash = _hash_token(g.raw_token)
            db = get_db()
            row = db.execute(
                "SELECT user_id, csrf_token, last_seen, expires_at "
                "FROM sessions WHERE id_hash = ?",
                (id_hash,),
            ).fetchone()
            if row:
                expired = (
                    row["expires_at"] <= now
                    or row["last_seen"] + IDLE_TIMEOUT <= now
                )
                if expired:
                    db.execute("DELETE FROM sessions WHERE id_hash = ?", (id_hash,))
                    db.commit()
                else:
                    g.user_id = row["user_id"]
                    g.session_id_hash = id_hash
                    g.csrf_token = row["csrf_token"]
                    if now - row["last_seen"] >= LAST_SEEN_UPDATE_INTERVAL:
                        db.execute(
                            "UPDATE sessions SET last_seen = ? WHERE id_hash = ?",
                            (now, id_hash),
                        )
                        db.commit()

        # CSRF defences for state-changing methods.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # 1) Same-origin check (Origin header is sent by browsers on unsafe requests).
            origin = request.headers.get("Origin")
            if origin:
                origin = origin.rstrip("/")
                same_host = urlparse(origin).netloc == request.host
                if not same_host and origin not in ALLOWED_ORIGINS:
                    return error("Cross-origin request blocked.", 403)
            # 2) JSON only: forces a CORS preflight for cross-site callers and
            #    kills classic form-based CSRF.
            if not request.is_json:
                return error("Content-Type must be application/json.", 415)
            # 3) Synchronizer token for authenticated requests. /login and
            #    /register are pre-auth endpoints, protected by checks 1-2 (a
            #    stale cookie must not block someone from logging in again).
            if g.user_id is not None and request.endpoint not in ("login", "register"):
                supplied = request.headers.get("X-CSRF-Token", "")
                if not hmac.compare_digest(supplied, g.csrf_token or ""):
                    return error("Missing or invalid CSRF token.", 403)

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if COOKIE_SECURE:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        resp.headers.pop("Server", None)
        return resp

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # ------------------------------ error handling -------------------------- #

    def error(message: str, status: int):
        return jsonify({"error": message}), status

    @app.errorhandler(ValidationError)
    def handle_validation(e):
        return error(str(e), 400)

    @app.errorhandler(400)
    def _400(_e):
        return error("Bad request.", 400)

    @app.errorhandler(404)
    def _404(_e):
        return error("Not found.", 404)

    @app.errorhandler(405)
    def _405(_e):
        return error("Method not allowed.", 405)

    @app.errorhandler(413)
    def _413(_e):
        return error("Request too large.", 413)

    @app.errorhandler(Exception)
    def _500(e):
        # Log details server-side; never leak internals to clients.
        app.logger.exception("Unhandled error: %s", type(e).__name__)
        return error("Internal server error.", 500)

    # ------------------------------ auth decorator -------------------------- #

    def login_required(view):
        from functools import wraps

        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user_id is None:
                return error("Authentication required.", 401)
            return view(*args, **kwargs)

        return wrapper

    # --------------------------------- routes ------------------------------- #

    @app.post("/register")
    def register():
        data = read_json_body()
        username = validate_username(data.get("username"))
        password = validate_new_password(data.get("password"), username)

        pw_hash = generate_password_hash(password, method=HASH_METHOD)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, int(time.time())),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Registration inherently reveals existence; consider email-based
            # verification if enumeration is a concern for your threat model.
            return error("Username is not available.", 409)
        return jsonify({"message": "Account created."}), 201

    @app.post("/login")
    def login():
        data = read_json_body()
        # Generic message for all failures below to avoid user enumeration.
        generic = lambda: error("Invalid credentials or account temporarily locked.", 401)
        try:
            username = validate_username(data.get("username"))
            password = validate_login_password(data.get("password"))
        except ValidationError:
            return generic()

        db = get_db()
        now = int(time.time())
        user = db.execute(
            "SELECT id, password_hash, failed_logins, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        stored_hash = user["password_hash"] if user else _DUMMY_HASH
        password_ok = check_password_hash(stored_hash, password)  # constant-time compare

        if user is None:
            return generic()

        if user["locked_until"] > now:
            return generic()

        if not password_ok:
            failed = user["failed_logins"] + 1
            locked_until = now + LOCKOUT_SECS if failed >= MAX_FAILED_LOGINS else 0
            if locked_until:
                failed = 0
            db.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (failed, locked_until, user["id"]),
            )
            db.commit()
            return generic()

        # Success: reset counters, rotate session (prevents fixation).
        db.execute(
            "UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?",
            (user["id"],),
        )
        destroy_session_by_token(g.raw_token)
        purge_expired_sessions()

        # Transparently upgrade hash parameters/algorithm if policy changed.
        if not stored_hash.startswith(HASH_METHOD + ":"):
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password, method=HASH_METHOD), user["id"]),
            )

        token, csrf = create_session(user["id"])
        db.commit()

        resp = make_response(jsonify({"message": "Logged in.", "csrf_token": csrf}))
        return set_session_cookie(resp, token)

    @app.post("/logout")
    @login_required
    def logout():
        destroy_session_by_token(g.raw_token)
        get_db().commit()
        resp = make_response(jsonify({"message": "Logged out."}))
        return clear_session_cookie(resp)

    @app.get("/me")
    @login_required
    def me():
        row = get_db().execute(
            "SELECT username, created_at FROM users WHERE id = ?", (g.user_id,)
        ).fetchone()
        if row is None:  # user deleted but session survived (shouldn't happen)
            return error("Authentication required.", 401)
        # Returning the CSRF token here lets a page reload re-obtain it. It is
        # safe: the response is same-origin-only and requires the session cookie.
        return jsonify(
            {
                "username": row["username"],
                "created_at": row["created_at"],
                "csrf_token": g.csrf_token,
            }
        )

    @app.post("/change-password")
    @login_required
    def change_password():
        data = read_json_body()
        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE id = ?", (g.user_id,)
        ).fetchone()
        if user is None:
            return error("Authentication required.", 401)

        current = validate_login_password(data.get("current_password"))
        if not check_password_hash(user["password_hash"], current):
            return error("Current password is incorrect.", 403)
        new_pw = validate_new_password(data.get("new_password"), user["username"])

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_pw, method=HASH_METHOD), user["id"]),
        )
        # Invalidate every other session; rotate the current one.
        destroy_user_sessions(user["id"])
        token, csrf = create_session(user["id"])
        db.commit()

        resp = make_response(
            jsonify({"message": "Password changed.", "csrf_token": csrf})
        )
        return set_session_cookie(resp, token)

    return app


app = create_app()

if __name__ == "__main__":
    # Development server only. Never run with debug=True or expose publicly;
    # use a production WSGI server behind HTTPS instead.
    app.run(host="127.0.0.1", port=5000, debug=False)