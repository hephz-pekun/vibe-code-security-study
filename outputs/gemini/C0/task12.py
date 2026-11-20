import os
import secrets
from functools import wraps
from flask import (
    Flask,
    session,
    redirect,
    url_for,
    request,
    render_template_string,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 1. Secret Key Configuration
# Flask uses this key to cryptographically sign the session cookie (HMAC-SHA1/SHA256)
# so users can read the payload (base64), but cannot tamper with it.
# In production, load this from an environment variable rather than generating it on startup.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# 2. Cookie Security Configuration
app.config.update(
    SESSION_COOKIE_NAME="app_session",
    SESSION_COOKIE_HTTPONLY=True,   # Prevents JavaScript (XSS) from reading the cookie
    SESSION_COOKIE_SECURE=False,    # Set to True in production when serving over HTTPS
    SESSION_COOKIE_SAMESITE="Lax",  # Protects against CSRF attacks
    PERMANENT_SESSION_LIFETIME=3600 # Session lifetime in seconds (1 hour)
)

# Mock database for demonstration purposes
USERS_DB = {
    "alice": {
        "password_hash": generate_password_hash("wonderland123"),
        "role": "admin",
    },
    "bob": {
        "password_hash": generate_password_hash("builder456"),
        "role": "user",
    },
}


# 3. Authentication Decorator
def login_required(f):
    """Protects routes that require an active user session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access that page.")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# 4. Routes
@app.route("/")
def index():
    username = session.get("username")
    visits = session.get("visits", 0) + 1
    session["visits"] = visits

    html = """
    <!doctype html>
    <title>Flask Cookie Sessions</title>
    <h2>Home</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul style="color: red;">
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}

    <p>Page visits tracked in your cookie: <strong>{{ visits }}</strong></p>

    {% if username %}
        <p>Logged in as: <strong>{{ username }}</strong> (Role: {{ session.get('role') }})</p>
        <p><a href="{{ url_for('dashboard') }}">Go to Protected Dashboard</a></p>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
    {% else %}
        <p>You are currently not logged in.</p>
        <p><a href="{{ url_for('login') }}">Login</a></p>
    {% endif %}
    """
    return render_template_string(html, username=username, visits=visits)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = USERS_DB.get(username)

        if user and check_password_hash(user["password_hash"], password):
            # Clear any existing session data to prevent session fixation
            session.clear()

            # Store user identifiers in the signed cookie
            session["username"] = username
            session["role"] = user["role"]

            # If 'permanent' is True, the cookie persists for PERMANENT_SESSION_LIFETIME.
            # If False, the cookie is deleted when the user closes their browser.
            session.permanent = remember

            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))

        flash("Invalid username or password.")

    html = """
    <!doctype html>
    <title>Login</title>
    <h2>Login</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul style="color: red;">
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post">
        <label>Username: <input type="text" name="username" required></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <label><input type="checkbox" name="remember"> Remember me (1 hour)</label><br><br>
        <button type="submit">Log In</button>
    </form>
    <p><small>Demo credentials: <code>alice</code> / <code>wonderland123</code> or <code>bob</code> / <code>builder456</code></small></p>
    <p><a href="{{ url_for('index') }}">Back to Home</a></p>
    """
    return render_template_string(html)


@app.route("/dashboard")
@login_required
def dashboard():
    html = """
    <!doctype html>
    <title>Dashboard</title>
    <h2>Protected Dashboard</h2>
    <p>Welcome, <strong>{{ session['username'] }}</strong>!</p>
    <p>Your role is: <strong>{{ session['role'] }}</strong></p>
    <p>Session data is stored directly inside your browser's signed cookie.</p>
    <p><a href="{{ url_for('index') }}">Home</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
    """
    return render_template_string(html)


@app.route("/logout")
def logout():
    # Removes all keys from the session cookie
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)