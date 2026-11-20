import os
import html
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import (
    Flask,
    request,
    jsonify,
    session,
    render_template_string,
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)

# Never hardcode secrets. Set this environment variable in production.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set."
    )

DATABASE = "app.db"

# Allow outbound requests only to approved domains.
# Configure via environment variable:
# PREVIEW_ALLOWED_HOSTS=example.com,www.example.com
ALLOWED_PREVIEW_HOSTS = {
    host.strip().lower()
    for host in os.environ.get(
        "PREVIEW_ALLOWED_HOSTS",
        "example.com"
    ).split(",")
    if host.strip()
}

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


init_db()

# -----------------------------------------------------------------------------
# Security Helpers
# -----------------------------------------------------------------------------

def is_private_or_local_ip(ip_str: str) -> bool:
    """
    Prevent SSRF to internal services.
    """
    ip = ipaddress.ip_address(ip_str)

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_and_resolve_url(url: str) -> str:
    """
    Validate URL, enforce an allowlist, and block requests
    to local/internal networks.
    """
    if not url or len(url) > 2048:
        raise ValueError("Invalid URL length.")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Hostname is required.")

    hostname = parsed.hostname.lower()

    # Explicit allowlist to mitigate SSRF.
    if hostname not in ALLOWED_PREVIEW_HOSTS:
        raise ValueError("Host is not permitted.")

    try:
        addr_info = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        raise ValueError("Unable to resolve hostname.")

    for entry in addr_info:
        ip_addr = entry[4][0]

        if is_private_or_local_ip(ip_addr):
            raise ValueError(
                "Requests to private or local addresses are not allowed."
            )

    return url


def login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401

        return func(*args, **kwargs)

    return wrapper


# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if len(username) > 100:
        return jsonify({"error": "Username too long"}), 400

    if len(password) < 12:
        return jsonify(
            {"error": "Password must be at least 12 characters"}
        ), 400

    password_hash = generate_password_hash(
        password,
        method="scrypt"
    )

    try:
        conn = get_db()

        conn.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        conn.commit()

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    finally:
        conn.close()

    return jsonify({"message": "User registered"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()

    user = conn.execute(
        """
        SELECT id, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    session.clear()
    session["user_id"] = user["id"]

    return jsonify({"message": "Login successful"})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


# -----------------------------------------------------------------------------
# URL Preview Endpoint
# -----------------------------------------------------------------------------

@app.get("/preview")
@login_required
def preview():
    url = request.args.get("url", "").strip()

    try:
        validated_url = validate_and_resolve_url(url)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    try:
        response = requests.get(
            validated_url,
            timeout=5,
            allow_redirects=False,
            headers={
                "User-Agent": "SecurePreviewBot/1.0"
            },
        )

        response.raise_for_status()

    except requests.RequestException:
        return jsonify(
            {"error": "Unable to retrieve URL"}
        ), 502

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "text/html" not in content_type:
        return jsonify(
            {"error": "Only HTML pages can be previewed"}
        ), 400

    page_content = response.text[:5000]

    escaped_preview = html.escape(page_content)

    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
            <title>Page Preview</title>
        </head>
        <body>
            <h1>Preview</h1>
            <p><strong>URL:</strong> {{ url }}</p>
            <pre style="white-space: pre-wrap;">{{ preview }}</pre>
        </body>
        </html>
        """,
        url=validated_url,
        preview=escaped_preview,
    )


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )