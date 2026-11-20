#!/usr/bin/env python3
"""
Secure Single-File Flask Weather Application (OWASP Top 10 Aligned).

Setup & Run:
    pip install flask requests werkzeug
    export OPENWEATHER_API_KEY="your_api_key_here"
    export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    python3 weather_app.py
"""

import hmac
import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

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
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration & Safe Defaults (OWASP A02: Security Misconfiguration)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("WEATHER_DB_PATH", BASE_DIR / "weather_secure.db"))

# Fixed upstream endpoint prevents Server-Side Request Forgery (OWASP A01)
OPENWEATHER_BASE_URL = "https://api.openweathermap.org/data/2.5/weather"
REQUEST_TIMEOUT_SECONDS = (3.0, 5.0)  # (connect_timeout, read_timeout)

# Strict input validation rules (OWASP A05: Injection / Input Validation)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
# Allows letters, spaces, hyphens, periods, apostrophes, and optional ",CC" country code
CITY_PATTERN = re.compile(r"^[a-zA-Z\u00C0-\u017F][a-zA-Z\u00C0-\u017F\s\-'.]{0,60}(?:,[a-zA-Z]{2})?$")
ALLOWED_UNITS = {"imperial", "metric"}
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure_weather_app")


def get_required_api_key() -> str:
    """Retrieve the API key from the environment without hardcoding secrets."""
    api_key = os.environ.get("OPENWEATHER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "OPENWEATHER_API_KEY environment variable is required and must not be empty."
        )
    return api_key


def create_app() -> Flask:
    app = Flask(__name__)

    # Fail-safe secret key handling (OWASP A04: Cryptographic Failures)
    configured_secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if len(configured_secret) < 32:
        logger.warning(
            "FLASK_SECRET_KEY not set or shorter than 32 chars; generating ephemeral runtime key."
        )
        configured_secret = secrets.token_hex(32)

    # Safe defaults: debug disabled, hardened session cookies, bounded payload size
    app.config.update(
        SECRET_KEY=configured_secret,
        DEBUG=False,
        TESTING=False,
        MAX_CONTENT_LENGTH=16 * 1024,  # 16 KB max request body
        SESSION_COOKIE_NAME="__Host-weather_session"
        if os.environ.get("HTTPS_ENABLED") == "1"
        else "weather_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED") == "1",
        PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    )

    init_db()

    # -----------------------------------------------------------------------
    # Database Helpers (OWASP A05: Parameterized Queries)
    # -----------------------------------------------------------------------
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(exception: BaseException | None = None) -> None:
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    # -----------------------------------------------------------------------
    # Security Headers & CSRF Protection (OWASP A01 / A02)
    # -----------------------------------------------------------------------
    def get_csrf_token() -> str:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def validate_csrf() -> None:
        expected = session.get("_csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not expected or not submitted or not hmac.compare_digest(expected, submitted):
            logger.warning("CSRF validation failed for endpoint=%s", request.endpoint)
            abort(403)

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.after_request
    def apply_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def login_required(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    # -----------------------------------------------------------------------
    # Authentication Routes (OWASP A04 & A07)
    # -----------------------------------------------------------------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not USERNAME_PATTERN.fullmatch(username):
                flash(
                    "Username must be 3–32 characters (letters, numbers, underscores only).",
                    "error",
                )
                return render_template_string(AUTH_TEMPLATE, mode="Register"), 400

            if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
                flash(
                    f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.",
                    "error",
                )
                return render_template_string(AUTH_TEMPLATE, mode="Register"), 400

            # Strong salted password hash (scrypt via Werkzeug)
            password_hash = generate_password_hash(password, method="scrypt")
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, password_hash, utc_now_iso()),
                )
                db.commit()
            except sqlite3.IntegrityError:
                flash("That username is already unavailable.", "error")
                return render_template_string(AUTH_TEMPLATE, mode="Register"), 409

            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))

        return render_template_string(AUTH_TEMPLATE, mode="Register")

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

            # Constant-time password verification; dummy hash mitigates timing enumeration
            dummy_hash = (
                "scrypt:32768:8:1$abcdefghijklmnop$"
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            candidate_hash = user["password_hash"] if user else dummy_hash
            is_valid = check_password_hash(candidate_hash, password)

            if user is None or not is_valid:
                logger.info("Failed login attempt for username=%r", username[:32])
                flash("Invalid username or password.", "error")
                return render_template_string(AUTH_TEMPLATE, mode="Log In"), 401

            # Regenerate session state on login to prevent session fixation
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            get_csrf_token()
            return redirect(url_for("index"))

        return render_template_string(AUTH_TEMPLATE, mode="Log In")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        validate_csrf()
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    # -----------------------------------------------------------------------
    # Weather Lookup Route (OWASP A01, A05, A10)
    # -----------------------------------------------------------------------
    @app.route("/", methods=["GET", "POST"])
    @login_required
    def index():
        weather_data: dict[str, Any] | None = None
        db = get_db()
        user_id = session["user_id"]

        if request.method == "POST":
            validate_csrf()
            raw_city = request.form.get("city", "").strip()
            units = request.form.get("units", "imperial").strip().lower()

            if units not in ALLOWED_UNITS:
                units = "imperial"

            if not CITY_PATTERN.fullmatch(raw_city):
                flash(
                    "Enter a valid city name (e.g., 'Rosenberg,US' or 'London').",
                    "error",
                )
            else:
                try:
                    weather_data = fetch_current_weather(raw_city, units)
                    db.execute(
                        """
                        INSERT INTO search_history
                            (user_id, city_query, resolved_name, temp, units, description, searched_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_id,
                            raw_city,
                            weather_data["location"],
                            weather_data["temp"],
                            units,
                            weather_data["description"],
                            utc_now_iso(),
                        ),
                    )
                    db.commit()
                except WeatherLookupError as exc:
                    flash(str(exc), "error")

        # Parameterized query scoped strictly to the authenticated user_id (OWASP A01)
        history = db.execute(
            """
            SELECT resolved_name, temp, units, description, searched_at
            FROM search_history
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (user_id,),
        ).fetchall()

        return render_template_string(
            DASHBOARD_TEMPLATE,
            username=session.get("username", ""),
            weather=weather_data,
            history=history,
        )

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def handle_http_error(err):
        code = getattr(err, "code", 500)
        return (
            render_template_string(
                ERROR_TEMPLATE,
                code=code,
                message="Request could not be completed safely.",
            ),
            code,
        )

    return app


# ---------------------------------------------------------------------------
# Upstream API Integration (OWASP A01, A02, A10)
# ---------------------------------------------------------------------------
class WeatherLookupError(Exception):
    """Safe, user-facing weather lookup exception."""


def fetch_current_weather(city: str, units: str) -> dict[str, Any]:
    """Query OpenWeatherMap safely without leaking API keys or internal stack traces."""
    api_key = get_required_api_key()
    params = {
        "q": city,
        "units": units,
        "appid": api_key,
    }

    try:
        response = requests.get(
            OPENWEATHER_BASE_URL,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,  # Prevent redirect-based SSRF or header leakage
        )
    except requests.Timeout:
        logger.warning("Upstream weather API timed out for city=%r", city)
        raise WeatherLookupError("Weather service timed out. Please try again.")
    except requests.RequestException as exc:
        # Never log exc directly if it contains the full request URL with appid
        logger.error("Network error calling weather API: %s", type(exc).__name__)
        raise WeatherLookupError("Unable to reach the weather service.")

    if response.status_code == 404:
        raise WeatherLookupError("City not found. Check spelling or include country code (e.g., Paris,FR).")
    if response.status_code == 401:
        logger.error("Weather API rejected configured API key (HTTP 401).")
        raise WeatherLookupError("Weather service authentication is misconfigured.")
    if response.status_code == 429:
        raise WeatherLookupError("Weather rate limit reached. Please wait a moment and retry.")
    if response.status_code != 200:
        logger.error("Unexpected weather API status=%s", response.status_code)
        raise WeatherLookupError("Weather data is temporarily unavailable.")

    try:
        payload = response.json()
        main_block = payload["main"]
        weather_list = payload["weather"]
        if not isinstance(weather_list, list) or not weather_list:
            raise KeyError("weather")

        unit_symbol = "°F" if units == "imperial" else "°C"
        speed_unit = "mph" if units == "imperial" else "m/s"
        country = payload.get("sys", {}).get("country", "")
        name = payload.get("name", city)
        location_label = f"{name}, {country}" if country else name

        return {
            "location": location_label,
            "temp": f"{round(float(main_block['temp']), 1)}{unit_symbol}",
            "feels_like": f"{round(float(main_block['feels_like']), 1)}{unit_symbol}",
            "humidity": f"{int(main_block['humidity'])}%",
            "wind": f"{round(float(payload.get('wind', {}).get('speed', 0.0)), 1)} {speed_unit}",
            "description": str(weather_list[0].get("description", "Unknown")).title(),
        }
    except (ValueError, KeyError, TypeError):
        logger.error("Malformed JSON received from upstream weather API.")
        raise WeatherLookupError("Received invalid data from weather provider.")


def init_db() -> None:
    """Initialize SQLite schema with parameterized/static DDL."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS search_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                city_query TEXT NOT NULL,
                resolved_name TEXT NOT NULL,
                temp TEXT NOT NULL,
                units TEXT NOT NULL,
                description TEXT NOT NULL,
                searched_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Auto-Escaped Jinja2 Templates (OWASP A05: XSS Prevention)
# ---------------------------------------------------------------------------
AUTH_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ mode }} - Secure Weather</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 420px; margin: 4rem auto; padding: 0 1rem; color: #111; }
    form { display: flex; flex-direction: column; gap: 0.75rem; }
    input, button { padding: 0.6rem; font-size: 1rem; }
    .flash-error { color: #b00020; background: #fdecea; padding: 0.6rem; border-radius: 4px; }
    .flash-success { color: #1b5e20; background: #e8f5e9; padding: 0.6rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>{{ mode }}</h1>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, msg in messages %}
      <p class="flash-{{ category }}">{{ msg }}</p>
    {% endfor %}
  {% endwith %}
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Username
      <input type="text" name="username" required minlength="3" maxlength="32" pattern="[a-zA-Z0-9_]{3,32}">
    </label>
    <label>Password
      <input type="password" name="password" required minlength="12" maxlength="128">
    </label>
    <button type="submit">{{ mode }}</button>
  </form>
  {% if mode == 'Log In' %}
    <p>Need an account? <a href="{{ url_for('register') }}">Register</a></p>
  {% else %}
    <p>Already have an account? <a href="{{ url_for('login') }}">Log In</a></p>
  {% endif %}
</body>
</html>
"""

DASHBOARD_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Weather Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 680px; margin: 2.5rem auto; padding: 0 1rem; color: #111; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
    form.search { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
    input, select, button { padding: 0.55rem; font-size: 1rem; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin-bottom: 1.5rem; background: #fafafa; }
    .flash-error { color: #b00020; background: #fdecea; padding: 0.6rem; border-radius: 4px; }
    .flash-success { color: #1b5e20; background: #e8f5e9; padding: 0.6rem; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #e5e5e5; }
  </style>
</head>
<body>
  <header>
    <div>Signed in as <strong>{{ username }}</strong></div>
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button type="submit">Log Out</button>
    </form>
  </header>

  <h1>Current Weather</h1>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, msg in messages %}
      <p class="flash-{{ category }}">{{ msg }}</p>
    {% endfor %}
  {% endwith %}

  <form class="search" method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="city" placeholder="City or City,CC (e.g., Rosenberg,US)" required maxlength="64">
    <select name="units" aria-label="Temperature Units">
      <option value="imperial">Fahrenheit (°F)</option>
      <option value="metric">Celsius (°C)</option>
    </select>
    <button type="submit">Check Weather</button>
  </form>

  {% if weather %}
    <div class="card">
      <h2>{{ weather.location }}</h2>
      <p><strong>Condition:</strong> {{ weather.description }}</p>
      <p><strong>Temperature:</strong> {{ weather.temp }} (Feels like {{ weather.feels_like }})</p>
      <p><strong>Humidity:</strong> {{ weather.humidity }} | <strong>Wind:</strong> {{ weather.wind }}</p>
    </div>
  {% endif %}

  <h2>Your Recent Searches</h2>
  {% if history %}
    <table>
      <thead>
        <tr><th>Location</th><th>Temp</th><th>Condition</th><th>Time</th></tr>
      </thead>
      <tbody>
        {% for row in history %}
          <tr>
            <td>{{ row['resolved_name'] }}</td>
            <td>{{ row['temp'] }}</td>
            <td>{{ row['description'] }}</td>
            <td>{{ row['searched_at'] }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% else %}
    <p>No weather lookups recorded yet.</p>
  {% endif %}
</body>
</html>
"""

ERROR_TEMPLATE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Error {{ code }}</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto;">
  <h1>Error {{ code }}</h1>
  <p>{{ message }}</p>
  <p><a href="{{ url_for('index') }}">Return Home</a></p>
</body>
</html>
"""

if __name__ == "__main__":
    # Fail fast at startup if the required API key is missing
    get_required_api_key()
    application = create_app()
    # Bind strictly to localhost by default; place behind a TLS reverse proxy in production
    application.run(host="127.0.0.1", port=5000, debug=False)