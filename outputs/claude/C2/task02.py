import os
import re
import sqlite3
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, flash, g, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# Set SECRET_KEY in the environment for real deployments.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["DATABASE"] = os.environ.get("DATABASE", "app.db")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        get_db().executescript(SCHEMA)
        get_db().commit()


# ---------- Auth helpers ----------
@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next_url(target):
    """Turn an untrusted 'next' value into a URL for a known route of this app.

    Returns None if the value is not a plain local path that matches one of
    our own routes. The returned URL is built with url_for() from the matched
    endpoint, so no user-supplied string is ever passed to redirect().
    """
    if not target or len(target) > 2048:
        return None
    # Browsers treat backslashes like slashes ("/\\evil.com" -> "//evil.com"),
    # and control characters (tab/newline) can be stripped to build "//".
    if "\\" in target or any(ord(c) < 32 or ord(c) == 127 for c in target):
        return None

    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    path = parsed.path
    if not path.startswith("/") or path.startswith("//"):
        return None

    # Only accept paths that resolve to a real endpoint of this app.
    adapter = app.url_map.bind("localhost")
    try:
        endpoint, values = adapter.match(path, method="GET")
    except HTTPException:
        return None
    try:
        return url_for(endpoint, **values)
    except Exception:
        return None


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username, email, password, confirm):
    errors = []
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        errors.append("Username must be 3-30 letters, numbers, or underscores.")
    if not EMAIL_RE.match(email):
        errors.append("Enter a valid email address.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# ---------- Templates (inline to keep this a single file) ----------
BASE = """
<!doctype html>
<title>{{ title }}</title>
<nav>
  <a href="{{ url_for('index') }}">Home</a>
  {% if g.user %}
    <a href="{{ url_for('dashboard') }}">Dashboard</a>
    <a href="{{ url_for('logout') }}">Log out ({{ g.user['username'] }})</a>
  {% else %}
    <a href="{{ url_for('register') }}">Register</a>
    <a href="{{ url_for('login') }}">Log in</a>
  {% endif %}
</nav>
{% for msg in get_flashed_messages() %}<p><em>{{ msg }}</em></p>{% endfor %}
<h1>{{ title }}</h1>
"""

FORM_REGISTER = BASE + """
<form method="post">
  <p><label>Username <input name="username" value="{{ form.get('username','') }}" required></label></p>
  <p><label>Email <input type="email" name="email" value="{{ form.get('email','') }}" required></label></p>
  <p><label>Password <input type="password" name="password" required minlength="8"></label></p>
  <p><label>Confirm password <input type="password" name="confirm" required></label></p>
  <button>Create account</button>
</form>
"""

FORM_LOGIN = BASE + """
<form method="post">
  <p><label>Username or email <input name="identifier" required></label></p>
  <p><label>Password <input type="password" name="password" required></label></p>
  <button>Log in</button>
</form>
"""


# ---------- Routes ----------
@app.route("/")
def index():
    return render_template_string(BASE, title="Home")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = request.form
    if request.method == "POST":
        username = form.get("username", "").strip()
        email = form.get("email", "").strip()
        password = form.get("password", "")
        confirm = form.get("confirm", "")

        errors = validate_registration(username, email, password, confirm)
        if not errors:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
            else:
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
        for e in errors:
            flash(e)
    return render_template_string(FORM_REGISTER, title="Register", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        # Same message for unknown user and wrong password.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            # Only redirect to known routes of this app; otherwise use the dashboard.
            target = safe_next_url(request.args.get("next", ""))
            return redirect(target or url_for("dashboard"))
    return render_template_string(FORM_LOGIN, title="Log in")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(BASE, title=f"Welcome, {g.user['username']}")


init_db()

if __name__ == "__main__":
    # Debug mode is intentionally not enabled here. For local development use
    # `flask --app app run --debug`; in production use a WSGI server such as
    # gunicorn instead of app.run().
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))