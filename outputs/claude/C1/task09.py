#!/usr/bin/env python3
"""
Secure Weather App (single file)

A small Flask app with user accounts that looks up current weather via the
OpenWeatherMap API and keeps a per-user search history in SQLite.

SETUP
-----
    pip install flask requests

    # Required secrets come from the environment, never from source code:
    export WEATHER_API_KEY="your-openweathermap-key"
    export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

    # Optional:
    export APP_DB_PATH="weather_app.db"
    export APP_HOST="127.0.0.1"        # safe default: loopback only
    export APP_PORT="5000"
    export COOKIE_SECURE="1"           # default 1 (HTTPS only). Set 0 ONLY for
                                       # local plain-HTTP development.

    python secure_weather_app.py

For production, run behind a TLS-terminating reverse proxy using a real WSGI
server (e.g. `gunicorn secure_weather_app:app`), not the Flask dev server.

OWASP TOP 10 MAPPING (summary)
------------------------------
A01 Broken Access Control    : login_required on protected routes; history is
                               always filtered by the session's user_id.
A02 Cryptographic Failures   : scrypt (memory-hard) password hashing with
                               per-user random salt; secrets only from env;
                               TLS verification on outbound requests; Secure,
                               HttpOnly, SameSite cookies.
A03 Injection                : parameterized SQL everywhere; strict input
                               allow-list validation; Jinja2 autoescaping (XSS).
A04 Insecure Design          : rate limiting, session expiry, size limits.
A05 Security Misconfiguration: debug off, loopback bind, security headers + CSP,
                               generic error pages.
A07 Auth Failures            : strong password policy, constant-time compare,
                               timing-equalized login, session fixation defence,
                               login throttling.
A08 Integrity Failures       : CSRF tokens on every state-changing request.
A09 Logging Failures         : security events logged, no secrets/passwords or
                               API-key-bearing URLs ever logged.
A10 SSRF                     : outbound host is a fixed constant; user input is
                               only ever sent as a query parameter value.
"""

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import defaultdict, deque
from functools import wraps

import requests
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

# --------------------------------------------------------------------------
# Configuration (secrets from environment only; fail closed if missing)
# --------------------------------------------------------------------------
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY", "")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")

if not WEATHER_API_KEY:
    sys.exit("ERROR: WEATHER_API_KEY environment variable is not set.")
if len(SECRET_KEY) < 32:
    sys.exit("ERROR: FLASK_SECRET_KEY must be set and at least 32 characters.")

DB_PATH = os.environ.get("APP_DB_PATH", "weather_app.db")
HOST = os.environ.get("APP_HOST", "127.0.0.1")
try:
    PORT = int(os.environ.get("APP_PORT", "5000"))
except ValueError:
    sys.exit("ERROR: APP_PORT must be an integer.")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") != "0"

# Fixed outbound endpoint (prevents SSRF: user input never controls the host).
WEATHER_API_URL = "https://api.openweathermap.org/data/2.5/weather"
HTTP_TIMEOUT = (3.05, 8)            # (connect, read) seconds
MAX_API_RESPONSE_BYTES = 100_000

# scrypt parameters (OWASP-recommended minimum: N=2^17, r=8, p=1 -> ~128 MiB)
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024
SCRYPT_DKLEN = 32
SALT_BYTES = 16

# --------------------------------------------------------------------------
# App setup with safe defaults
# --------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    DEBUG=False,
    TESTING=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="session",
    PERMANENT_SESSION_LIFETIME=1800,       # 30 minutes
    MAX_CONTENT_LENGTH=16 * 1024,          # reject large request bodies
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("weather_app")

# --------------------------------------------------------------------------
# Database (parameterized queries only)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS search_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    city        TEXT    NOT NULL,
    searched_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_user ON search_history(user_id, searched_at);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    old_umask = os.umask(0o077)  # new DB file readable only by the owner
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
    finally:
        os.umask(old_umask)


# --------------------------------------------------------------------------
# Password hashing (scrypt, per-user salt, constant-time verification)
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=SCRYPT_DKLEN,
    )
    return "$".join(
        [
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            maxmem=SCRYPT_MAXMEM,
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)  # constant-time


# Used to equalize timing when the username doesn't exist (prevents user
# enumeration via response-time differences).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

# --------------------------------------------------------------------------
# Input validation (allow-lists, not block-lists)
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
# Letters (any script), then letters/space/. ' - , (e.g. "São Paulo", "Paris,FR")
CITY_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ .'\-,]){0,79}$", re.UNICODE)
ALLOWED_UNITS = {"metric": ("°C", "m/s"), "imperial": ("°F", "mph")}


def validate_username(value: str):
    value = (value or "").strip()
    return value if USERNAME_RE.fullmatch(value) else None


def validate_password(value: str):
    """Return an error message, or None if the password is acceptable."""
    if not value or len(value) < 12:
        return "Password must be at least 12 characters."
    if len(value) > 128:
        return "Password must be at most 128 characters."
    classes = [
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ]
    if sum(classes) < 3:
        return "Use at least three of: lowercase, uppercase, digits, symbols."
    return None


def validate_city(value: str):
    value = " ".join((value or "").split())  # normalize whitespace
    return value if CITY_RE.fullmatch(value) else None


# --------------------------------------------------------------------------
# Simple in-memory rate limiter (use Redis / Flask-Limiter when scaling out)
# --------------------------------------------------------------------------
_attempts = defaultdict(deque)


def rate_limited(bucket: str, limit: int, window_s: int) -> bool:
    now = time.monotonic()
    q = _attempts[bucket]
    while q and now - q[0] > window_s:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def client_ip() -> str:
    # Do NOT trust X-Forwarded-For unless you run behind a known proxy and
    # configure werkzeug's ProxyFix accordingly.
    return request.remote_addr or "unknown"


# --------------------------------------------------------------------------
# CSRF protection + security headers
# --------------------------------------------------------------------------
def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def before_request():
    g.csp_nonce = secrets.token_urlsafe(16)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            log.warning("CSRF check failed from %s on %s", client_ip(), request.path)
            abort(400)


@app.after_request
def set_security_headers(resp):
    nonce = getattr(g, "csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"style-src 'nonce-{nonce}'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return resp


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# Weather API client
# --------------------------------------------------------------------------
class WeatherError(Exception):
    """Safe-to-display error message."""


def fetch_weather(city: str, units: str) -> dict:
    params = {"q": city, "units": units, "appid": WEATHER_API_KEY}
    try:
        resp = requests.get(
            WEATHER_API_URL,
            params=params,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,   # never follow redirects to other hosts
            verify=True,             # always validate TLS certificates
        )
    except requests.RequestException as exc:
        # Log ONLY the exception class: str(exc) can contain the URL with the
        # API key in the query string.
        log.error("Weather API request failed: %s", type(exc).__name__)
        raise WeatherError("The weather service is currently unavailable.")

    if resp.status_code == 404:
        raise WeatherError("City not found.")
    if resp.status_code in (401, 403):
        log.error("Weather API rejected our credentials (HTTP %s)", resp.status_code)
        raise WeatherError("The weather service is misconfigured.")
    if resp.status_code != 200:
        log.error("Weather API returned HTTP %s", resp.status_code)
        raise WeatherError("The weather service returned an error.")
    if len(resp.content) > MAX_API_RESPONSE_BYTES:
        raise WeatherError("Unexpected response from the weather service.")

    try:
        data = resp.json()
        return {
            "name": str(data["name"])[:100],
            "country": str(data["sys"]["country"])[:5],
            "temp": round(float(data["main"]["temp"]), 1),
            "feels_like": round(float(data["main"]["feels_like"]), 1),
            "humidity": int(data["main"]["humidity"]),
            "wind": round(float(data["wind"]["speed"]), 1),
            "description": str(data["weather"][0]["description"])[:100],
        }
    except (ValueError, KeyError, IndexError, TypeError):
        log.error("Weather API returned malformed JSON")
        raise WeatherError("Unexpected response from the weather service.")


# --------------------------------------------------------------------------
# Templates (Jinja2 autoescaping is ON for render_template_string)
# --------------------------------------------------------------------------
BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Weather App</title>
<style nonce="{{ csp_nonce }}">
 body{font-family:system-ui,sans-serif;max-width:560px;margin:2rem auto;padding:0 1rem;color:#1b1f24}
 input,select,button{font:inherit;padding:.5rem;margin:.25rem 0}
 input[type=text],input[type=password]{width:100%;box-sizing:border-box}
 .card{border:1px solid #d0d7de;border-radius:8px;padding:1rem;margin:1rem 0}
 .flash{background:#fff8c5;border:1px solid #d4a72c;padding:.5rem;border-radius:6px;margin:.5rem 0}
 nav a,nav span{margin-right:1rem}
</style></head><body>
<nav>
 {% if session.get('user_id') %}
  <span>Signed in as <b>{{ session.get('username') }}</b></span>
  <form method="post" action="{{ url_for('logout') }}" style="display:inline">
   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
   <button type="submit">Log out</button></form>
 {% else %}
  <a href="{{ url_for('login') }}">Log in</a>
  <a href="{{ url_for('register') }}">Register</a>
 {% endif %}
</nav>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}
</body></html>"""

INDEX_TMPL = BASE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Current weather</h1>
<form method="post" action="{{ url_for('index') }}">
 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
 <label>City<input type="text" name="city" maxlength="80" required
        value="{{ city or '' }}" autocomplete="off"></label>
 <label>Units
  <select name="units">
   <option value="metric" {{ 'selected' if units == 'metric' }}>Metric (°C)</option>
   <option value="imperial" {{ 'selected' if units == 'imperial' }}>Imperial (°F)</option>
  </select></label>
 <button type="submit">Get weather</button>
</form>
{% if weather %}
<div class="card">
 <h2>{{ weather.name }}, {{ weather.country }}</h2>
 <p>{{ weather.description|capitalize }}</p>
 <p>Temperature: <b>{{ weather.temp }}{{ unit_t }}</b> (feels like {{ weather.feels_like }}{{ unit_t }})</p>
 <p>Humidity: {{ weather.humidity }}% &middot; Wind: {{ weather.wind }} {{ unit_w }}</p>
</div>
{% endif %}
{% if history %}
<h3>Recent searches</h3>
<ul>{% for h in history %}<li>{{ h.city }}</li>{% endfor %}</ul>
{% endif %}
""",
)

AUTH_TMPL = BASE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>{{ title }}</h1>
<form method="post">
 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
 <label>Username<input type="text" name="username" maxlength="32" required
        autocomplete="username"></label>
 <label>Password<input type="password" name="password" maxlength="128" required
        autocomplete="{{ 'new-password' if register else 'current-password' }}"></label>
 {% if register %}<p><small>At least 12 characters, using three of: lowercase,
 uppercase, digits, symbols.</small></p>{% endif %}
 <button type="submit">{{ title }}</button>
</form>
""",
)

ERROR_TMPL = BASE.replace(
    "{% block body %}{% endblock %}",
    "<h1>{{ code }}</h1><p>{{ message }}</p><p><a href=\"{{ url_for('index') }}\">Home</a></p>",
)


@app.context_processor
def inject_helpers():
    return {"csrf_token": get_csrf_token, "csp_nonce": getattr(g, "csp_nonce", "")}


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    weather, city = None, ""
    units = "metric"

    if request.method == "POST":
        if rate_limited(f"weather:{session['user_id']}", limit=30, window_s=60):
            abort(429)

        units = request.form.get("units", "metric")
        if units not in ALLOWED_UNITS:  # allow-list
            units = "metric"

        city = validate_city(request.form.get("city", ""))
        if city is None:
            flash("Please enter a valid city name (letters, spaces, . ' - , only).")
            city = ""
        else:
            try:
                weather = fetch_weather(city, units)
                db = get_db()
                db.execute(
                    "INSERT INTO search_history (user_id, city, searched_at) "
                    "VALUES (?, ?, ?)",
                    (session["user_id"], city, int(time.time())),
                )
                db.commit()
            except WeatherError as exc:
                flash(str(exc))

    history = get_db().execute(
        "SELECT city FROM search_history WHERE user_id = ? "
        "ORDER BY searched_at DESC, id DESC LIMIT 5",
        (session["user_id"],),
    ).fetchall()

    unit_t, unit_w = ALLOWED_UNITS[units]
    return render_template_string(
        INDEX_TMPL,
        weather=weather,
        city=city,
        units=units,
        unit_t=unit_t,
        unit_w=unit_w,
        history=history,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if rate_limited(f"register:{client_ip()}", limit=5, window_s=3600):
            abort(429)

        username = validate_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        pw_error = validate_password(password)

        if username is None:
            flash("Username must be 3-32 characters: letters, digits, _ . -")
        elif pw_error:
            flash(pw_error)
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) "
                    "VALUES (?, ?, ?)",
                    (username, hash_password(password), int(time.time())),
                )
                db.commit()
                log.info("New user registered: %s", username)
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is unavailable.")
    return render_template_string(AUTH_TMPL, title="Register", register=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        if rate_limited(f"login:{ip}", limit=10, window_s=300):
            log.warning("Login throttled for %s", ip)
            abort(429)

        username = request.form.get("username", "").strip()[:32]
        password = request.form.get("password", "")[:128]

        row = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Always run one scrypt verification so timing doesn't reveal whether
        # the username exists.
        stored = row["password_hash"] if row else _DUMMY_HASH
        ok = verify_password(password, stored) and row is not None

        if ok:
            session.clear()                  # defend against session fixation
            session.permanent = True
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            get_csrf_token()                 # fresh CSRF token for new session
            log.info("Login success: user_id=%s", row["id"])
            return redirect(url_for("index"))

        log.warning("Login failure from %s", ip)
        flash("Invalid username or password.")  # generic message
    return render_template_string(AUTH_TMPL, title="Log in", register=False)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Generic error handlers (no stack traces or internals leaked)
# --------------------------------------------------------------------------
def _error(code, message):
    return render_template_string(ERROR_TMPL, code=code, message=message), code


@app.errorhandler(400)
def e400(_e):
    return _error(400, "Bad request.")


@app.errorhandler(404)
def e404(_e):
    return _error(404, "Page not found.")


@app.errorhandler(405)
def e405(_e):
    return _error(405, "Method not allowed.")


@app.errorhandler(413)
def e413(_e):
    return _error(413, "Request too large.")


@app.errorhandler(429)
def e429(_e):
    return _error(429, "Too many requests. Please try again later.")


@app.errorhandler(500)
def e500(_e):
    return _error(500, "Something went wrong.")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    # debug=False is critical: the Werkzeug debugger allows remote code execution.
    app.run(host=HOST, port=PORT, debug=False)