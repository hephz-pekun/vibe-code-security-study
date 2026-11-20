#!/usr/bin/env python3
"""
Secure URL-preview service (Flask).

Setup
-----
    pip install flask urllib3
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # Local development over plain HTTP only (never in production):
    export ALLOW_INSECURE_COOKIES=1
    python secure_preview.py

Try it
------
    curl -c jar -b jar -H 'Content-Type: application/json' \
         -d '{"username":"alice","password":"correct horse battery staple"}' \
         http://127.0.0.1:5000/register
    curl -c jar -b jar -H 'Content-Type: application/json' \
         -d '{"username":"alice","password":"correct horse battery staple"}' \
         http://127.0.0.1:5000/login
    curl -c jar -b jar -H 'Content-Type: application/json' \
         -d '{"url":"https://example.com"}' http://127.0.0.1:5000/preview

OWASP Top 10 mapping (summary)
------------------------------
A01 Broken Access Control      : /preview requires an authenticated session.
A02 Cryptographic Failures     : scrypt password hashing, Secure/HttpOnly cookies, HSTS,
                                 TLS certificate + hostname verification on outbound HTTPS.
A03 Injection                  : parameterized SQL only; strict input validation; JSON output
                                 (clients must render with textContent, never innerHTML).
A04 Insecure Design            : size/time/redirect limits, per-IP rate limiting.
A05 Security Misconfiguration  : debug off, secure headers, generic error messages,
                                 no secrets in code (SECRET_KEY from environment).
A07 Authentication Failures    : password policy, constant-time-ish login, session reset on
                                 login (anti fixation), short session lifetime, rate limits.
A09 Logging Failures           : security-relevant events logged without secrets.
A10 SSRF                       : scheme/port allow-list, DNS resolution + public-IP check,
                                 connection pinned to the validated IP (anti DNS-rebinding),
                                 every redirect re-validated, no credentials in URLs.
"""

import codecs
import ipaddress
import logging
import os
import re
import socket
import sqlite3
import threading
import time
from collections import defaultdict, deque, namedtuple
from datetime import timedelta
from functools import wraps
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import urllib3
from flask import Flask, g, jsonify, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Configuration (no hardcoded secrets; safe defaults)
# --------------------------------------------------------------------------- #

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("preview")


def _load_secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "")
    if len(key) < 32:
        raise RuntimeError(
            "SECRET_KEY environment variable is required (>= 32 chars). Generate one with: "
            "python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    return key


def _env_flag(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    return default if val is None else val.strip().lower() in {"1", "true", "yes"}


DATABASE_PATH = os.environ.get("DATABASE_PATH", "preview_app.db")
ALLOW_REGISTRATION = _env_flag("ALLOW_REGISTRATION", True)
SECURE_COOKIES = not _env_flag("ALLOW_INSECURE_COOKIES", False)  # secure by default

# Outbound fetch limits
ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}
ALLOWED_PORTS = {80, 443}
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 3
MAX_BODY_BYTES = 512 * 1024          # only the first 512 KiB is parsed
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
TOTAL_TIMEOUT = 10.0                  # wall-clock cap for the whole fetch
ALLOWED_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
USER_AGENT = "SecurePreviewBot/1.0 (+link preview)"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    MAX_CONTENT_LENGTH=16 * 1024,                 # reject large request bodies
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="__Host-session" if SECURE_COOKIES else "session",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    JSON_SORT_KEYS=False,
)

# --------------------------------------------------------------------------- #
# Database (parameterized queries only)
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.executescript(SCHEMA)
    try:
        os.chmod(DATABASE_PATH, 0o600)  # owner-only
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Simple in-memory rate limiter (use Redis / Flask-Limiter for multi-process)
# --------------------------------------------------------------------------- #

_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)


def rate_limit(scope: str, limit: int, window_seconds: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # NOTE: remote_addr is only trustworthy if you configure ProxyFix correctly
            # when running behind a reverse proxy.
            key = (scope, request.remote_addr)
            now = time.monotonic()
            with _rate_lock:
                hits = _rate_hits[key]
                while hits and now - hits[0] > window_seconds:
                    hits.popleft()
                if len(hits) >= limit:
                    log.warning("rate limit hit scope=%s ip=%s", scope, request.remote_addr)
                    return jsonify(error="Too many requests"), 429
                hits.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------- #
# Authentication helpers
# --------------------------------------------------------------------------- #

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN, MAX_PASSWORD_LEN = 12, 128
# Used so that unknown usernames cost the same as wrong passwords (timing side channel).
_DUMMY_HASH = generate_password_hash("not-a-real-password", method="scrypt")


def _json_body() -> dict:
    data = request.get_json(silent=True)  # requires Content-Type: application/json
    if not isinstance(data, dict):
        return {}
    return data


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Authentication required"), 401
        return fn(*args, **kwargs)
    return wrapper


@app.post("/register")
@rate_limit("register", limit=5, window_seconds=3600)
def register():
    if not ALLOW_REGISTRATION:
        return jsonify(error="Registration is disabled"), 403

    data = _json_body()
    username, password = data.get("username"), data.get("password")

    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        return jsonify(error="Username must be 3-32 chars: letters, digits, _ . -"), 400
    if (
        not isinstance(password, str)
        or not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN)
    ):
        return jsonify(
            error=f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters"
        ), 400

    pw_hash = generate_password_hash(password, method="scrypt")  # salted, memory-hard
    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username unavailable"), 409

    log.info("user registered username=%s", username)
    return jsonify(message="Registered"), 201


@app.post("/login")
@rate_limit("login", limit=10, window_seconds=300)
def login():
    data = _json_body()
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) \
            or len(username) > 64 or len(password) > MAX_PASSWORD_LEN:
        return jsonify(error="Invalid credentials"), 401

    row = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    stored = row["password_hash"] if row else _DUMMY_HASH
    ok = check_password_hash(stored, password)
    if not (row and ok):
        log.warning("failed login username=%r ip=%s", username[:64], request.remote_addr)
        return jsonify(error="Invalid credentials"), 401

    session.clear()                      # prevent session fixation
    session.permanent = True
    session["user_id"] = row["id"]
    return jsonify(message="Logged in")


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out")


# --------------------------------------------------------------------------- #
# SSRF-hardened fetching
# --------------------------------------------------------------------------- #

class UrlNotAllowed(Exception):
    """The user-supplied (or redirected-to) URL failed validation."""


class FetchError(Exception):
    """Network / protocol / content problem while fetching."""


Target = namedtuple("Target", "scheme hostname port path ips")

_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
# Ranges that embed IPv4 addresses and can be used to smuggle private targets.
_EXTRA_BLOCKED_NETS = [
    ipaddress.ip_network("64:ff9b::/96"),     # NAT64
    ipaddress.ip_network("64:ff9b:1::/48"),   # local-use NAT64
    ipaddress.ip_network("2002::/16"),        # 6to4
    ipaddress.ip_network("2001::/32"),        # Teredo
]


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip.version == n.version and ip in n for n in _EXTRA_BLOCKED_NETS)


def validate_url(raw_url) -> Target:
    """Validate a URL and resolve it to a set of *public* IP addresses."""
    if not isinstance(raw_url, str):
        raise UrlNotAllowed("URL must be a string")
    raw_url = raw_url.strip()
    if not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise UrlNotAllowed("Invalid URL length")
    if _CONTROL_OR_SPACE_RE.search(raw_url):
        raise UrlNotAllowed("Invalid characters in URL")

    try:
        parts = urlsplit(raw_url)
        port = parts.port
    except ValueError:
        raise UrlNotAllowed("Malformed URL")

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlNotAllowed("Only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise UrlNotAllowed("Credentials in URLs are not allowed")
    if not parts.hostname:
        raise UrlNotAllowed("Missing host")

    port = port or DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise UrlNotAllowed("Port not allowed")

    try:
        hostname = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise UrlNotAllowed("Invalid host name")

    # Resolve ourselves and validate *every* answer. Odd IP spellings (decimal,
    # octal, hex, IPv4-mapped IPv6) are normalised by the resolver, so we check
    # the final addresses rather than pattern-matching the string.
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UrlNotAllowed("Host could not be resolved")

    ips = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if not _is_public_ip(ip):
            log.warning("blocked non-public address host=%s ip=%s", hostname, ip)
            raise UrlNotAllowed("URL not allowed")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise UrlNotAllowed("Host could not be resolved")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme, hostname, port, path, ips)


def _open_pinned(target: Target, deadline: float):
    """Connect to a validated IP (not the hostname) so DNS can't change underneath us,
    while still using the hostname for SNI, certificate checks and the Host header."""
    last_exc = None
    for ip in target.ips:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("Timed out")
        timeout = urllib3.Timeout(
            connect=min(CONNECT_TIMEOUT, remaining), read=min(READ_TIMEOUT, remaining)
        )
        if target.scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                ip, port=target.port, timeout=timeout, retries=False, maxsize=1,
                cert_reqs="CERT_REQUIRED",
                server_hostname=target.hostname,
                assert_hostname=target.hostname,
            )
        else:
            pool = urllib3.HTTPConnectionPool(
                ip, port=target.port, timeout=timeout, retries=False, maxsize=1
            )
        try:
            resp = pool.urlopen(
                "GET",
                target.path,
                headers={
                    "Host": target.hostname,
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Encoding": "gzip, deflate",
                },
                redirect=False,
                retries=False,
                preload_content=False,
            )
            return pool, resp
        except (urllib3.exceptions.HTTPError, OSError) as exc:
            last_exc = exc
            pool.close()
    log.info("fetch failed host=%s err=%s", target.hostname, type(last_exc).__name__)
    raise FetchError("Connection failed")


def fetch_html(url: str):
    """Fetch a page safely. Returns (final_url, decoded_html)."""
    deadline = time.monotonic() + TOTAL_TIMEOUT
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        target = validate_url(current)          # re-validated on every hop
        pool, resp = _open_pinned(target, deadline)
        try:
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location or len(location) > MAX_URL_LENGTH:
                    raise FetchError("Bad redirect")
                current = urljoin(current, location)
                continue

            if resp.status != 200:
                raise FetchError("Upstream returned an error status")

            content_type = resp.headers.get("Content-Type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type not in ALLOWED_CONTENT_TYPES:
                raise FetchError("Unsupported content type")

            # Bound *decoded* bytes too, so compression bombs can't blow up memory.
            chunks, size = [], 0
            for chunk in resp.stream(8192, decode_content=True):
                if time.monotonic() > deadline:
                    raise FetchError("Timed out")
                size += len(chunk)
                if size > MAX_BODY_BYTES:
                    chunks.append(chunk[: len(chunk) - (size - MAX_BODY_BYTES)])
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)

            charset = "utf-8"
            m = re.search(r"charset=([A-Za-z0-9_.:-]{1,40})", content_type, re.I)
            if m:
                try:
                    charset = codecs.lookup(m.group(1)).name
                except LookupError:
                    pass
            try:
                text = raw.decode(charset, errors="replace")
            except (LookupError, UnicodeError, TypeError):
                text = raw.decode("utf-8", errors="replace")
            return current, text
        except (urllib3.exceptions.HTTPError, OSError):
            raise FetchError("Failed while reading response")
        finally:
            try:
                resp.close()
            finally:
                pool.close()

    raise FetchError("Too many redirects")


# --------------------------------------------------------------------------- #
# Metadata extraction (stdlib parser; output is plain text, never raw HTML)
# --------------------------------------------------------------------------- #

_WANTED_META = {
    "og:title", "og:description", "og:image", "og:site_name",
    "twitter:title", "twitter:description", "twitter:image", "description",
}
_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(text, limit: int):
    if not text:
        return None
    text = _WS_RE.sub(" ", _CTRL_RE.sub("", text)).strip()
    return text[:limit] or None


class _HeadParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta, self.title_parts = {}, []
        self._in_title = self._title_done = self.finished = False

    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self._title_done:
            self._in_title = True
        elif tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            key = (a.get("property") or a.get("name") or "").lower()
            if key in _WANTED_META and "content" in a:
                self.meta.setdefault(key, a["content"])
        elif tag == "body":
            self.finished = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title, self._title_done = False, True
        elif tag == "head":
            self.finished = True

    def handle_data(self, data):
        if self._in_title and sum(map(len, self.title_parts)) < 1000:
            self.title_parts.append(data)


def _safe_image_url(base_url: str, candidate):
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        return None
    absolute = urljoin(base_url, candidate.strip())
    try:
        parts = urlsplit(absolute)
    except ValueError:
        return None
    if parts.scheme not in ALLOWED_SCHEMES or not parts.hostname or parts.username:
        return None
    return absolute  # returned as data only; the server never fetches it


def extract_preview(final_url: str, html: str) -> dict:
    parser = _HeadParser()
    try:
        for i in range(0, len(html), 8192):
            parser.feed(html[i:i + 8192])
            if parser.finished:
                break
    except Exception:  # malformed markup must never crash the request
        pass

    m = parser.meta
    title = (m.get("og:title") or m.get("twitter:title") or "".join(parser.title_parts))
    description = (m.get("og:description") or m.get("twitter:description")
                   or m.get("description"))
    image = m.get("og:image") or m.get("twitter:image")
    return {
        "url": final_url,
        "title": _clean(title, 200),
        "description": _clean(description, 500),
        "site_name": _clean(m.get("og:site_name"), 100),
        "image": _safe_image_url(final_url, image),
    }


# --------------------------------------------------------------------------- #
# The preview endpoint
# --------------------------------------------------------------------------- #

@app.post("/preview")
@login_required
@rate_limit("preview", limit=30, window_seconds=60)
def preview():
    data = _json_body()
    url = data.get("url")
    try:
        final_url, html = fetch_html(url)
    except UrlNotAllowed as exc:
        return jsonify(error=str(exc)), 400
    except FetchError:
        # Deliberately vague: detailed errors would help attackers map internal networks.
        return jsonify(error="Could not fetch a preview for that URL"), 502

    log.info("preview user_id=%s host=%s", session.get("user_id"), urlsplit(final_url).hostname)
    return jsonify(preview=extract_preview(final_url, html))


# --------------------------------------------------------------------------- #
# Security headers & error handling
# --------------------------------------------------------------------------- #

@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if SECURE_COOKIES:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(HTTPException)
def handle_http_error(exc: HTTPException):
    return jsonify(error=exc.name), exc.code


@app.errorhandler(Exception)
def handle_unexpected_error(exc: Exception):
    log.exception("unhandled error")           # details go to logs only
    return jsonify(error="Internal server error"), 500


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

init_db()

if __name__ == "__main__":
    # Development server only. In production use a WSGI server (e.g. gunicorn)
    # behind a TLS-terminating reverse proxy. Never enable debug mode.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)