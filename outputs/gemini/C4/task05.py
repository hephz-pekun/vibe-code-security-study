import ipaddress
import os
import socket
import sqlite3
from urllib.parse import urlparse
import bcrypt
from bs4 import BeautifulSoup
from flask import Flask, g, jsonify, request
import requests

app = Flask(__name__)

# Avoid hardcoded secrets: load from environment variables with safe defaults
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "app.db")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB limit to prevent memory exhaustion
REQUEST_TIMEOUT = (3.0, 5.0)  # (connect timeout, read timeout) in seconds


# --- Database Helpers (Parameterized Queries & Password Hashing) ---


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS preview_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            requested_url TEXT NOT NULL,
            page_title TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.commit()


def create_user(username: str, plaintext_password: str):
    # Hash passwords with a strong adaptive algorithm (bcrypt)
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(plaintext_password.encode("utf-8"), salt)
    db = get_db()
    # Parameterized query prevents SQL injection
    db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    db.commit()


def verify_user(username: str, plaintext_password: str) -> bool:
    db = get_db()
    row = db.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return False
    return bcrypt.checkpw(plaintext_password.encode("utf-8"), row["password_hash"])


# --- Input Validation & SSRF Mitigation ---


def is_safe_ip(ip_str: str) -> bool:
    """Ensure the resolved IP address is globally routable (blocks SSRF to internal networks)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_global
            and not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
        )
    except ValueError:
        return False


def validate_and_resolve_url(raw_url: str):
    """Validate URL scheme, structure, and DNS resolution against SSRF."""
    if not raw_url or not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError("Invalid URL length or type.")

    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS schemes are allowed.")

    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname.")

    # Resolve all IP addresses for the hostname and verify each is public
    try:
        addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or 80)
    except socket.gaierror as exc:
        raise ValueError("Unable to resolve hostname.") from exc

    resolved_ips = {info[4][0] for info in addr_info}
    if not resolved_ips or not all(is_safe_ip(ip) for ip in resolved_ips):
        raise ValueError("Access to non-public or internal IP addresses is forbidden.")

    return parsed.geturl()


def fetch_safe_preview(url: str) -> dict:
    """Fetch external URL safely without following unvalidated redirects."""
    current_url = validate_and_resolve_url(url)

    # Manually handle redirects (max 3) so every hop is validated against SSRF
    for _ in range(3):
        with requests.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "SafeLinkPreviewBot/1.0"},
        ) as resp:
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("Location")
                if not location:
                    raise ValueError("Redirect response missing Location header.")
                current_url = validate_and_resolve_url(location)
                continue

            resp.raise_for_status()

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type.lower():
                raise ValueError("Target URL did not return an HTML document.")

            # Read response in chunks up to MAX_RESPONSE_BYTES
            chunks = []
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=8192):
                bytes_read += len(chunk)
                if bytes_read > MAX_RESPONSE_BYTES:
                    raise ValueError("Response size exceeds the maximum allowed limit.")
                chunks.append(chunk)

            html_content = b"".join(chunks).decode(
                resp.encoding or "utf-8", errors="replace"
            )
            soup = BeautifulSoup(html_content, "html.parser")

            title = (
                soup.title.string.strip()
                if soup.title and soup.title.string
                else "No title"
            )
            meta_desc = soup.find("meta", attrs={"name": "description"})
            description = (
                meta_desc["content"].strip()
                if meta_desc and meta_desc.get("content")
                else ""
            )

            return {
                "url": current_url,
                "title": title[:200],
                "description": description[:500],
            }

    raise ValueError("Too many redirects.")


# --- Security Headers ---


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# --- Endpoints ---


@app.route("/preview", methods=["POST"])
def preview_url():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415

    data = request.get_json(silent=True) or {}
    target_url = data.get("url")

    try:
        preview_data = fetch_safe_preview(target_url)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    except requests.RequestException:
        # Generic error message avoids leaking internal stack traces or network details
        return jsonify({"error": "Failed to fetch the requested URL."}), 502

    # Log the request using a parameterized query
    db = get_db()
    db.execute(
        "INSERT INTO preview_logs (requested_url, page_title) VALUES (?, ?)",
        (preview_data["url"], preview_data["title"]),
    )
    db.commit()

    return jsonify(preview_data), 200


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Safe default: debug mode is disabled in production
    app.run(host="127.0.0.1", port=5000, debug=False)