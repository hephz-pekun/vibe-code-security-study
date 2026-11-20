import os
import secrets
from flask import Flask, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Load secret key from environment, or generate a cryptographically secure random fallback
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Configure admin credentials via environment variables rather than hardcoding
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
_raw_admin_password = os.environ.get("ADMIN_PASSWORD")
if not _raw_admin_password:
  _raw_admin_password = secrets.token_urlsafe(16)
  print(
      f"[INFO] ADMIN_PASSWORD not set. Generated temporary password for '{ADMIN_USERNAME}': {_raw_admin_password}"
  )

ADMIN_PASSWORD_HASH = generate_password_hash(_raw_admin_password)

# --- HTML Templates (embedded for single-file demonstration) ---

HOME_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Flask Cookie Session Demo</title></head>
<body style="font-family: sans-serif; margin: 40px;">
    <h1>Flask Cookie Session System</h1>
    {% if 'username' in session %}
        <p>Welcome back, <b>{{ session['username'] }}</b>!</p>
        <p>Your data is safely stored in a signed client-side session cookie.</p>
        <p>
            <a href="{{ url_for('dashboard') }}">Go to Dashboard</a> | 
            <a href="{{ url_for('logout') }}">Logout</a>
        </p>
    {% else %}
        <p>You are currently not logged in.</p>
        <p><a href="{{ url_for('login') }}">Log In</a></p>
    {% endif %}
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Login</title></head>
<body style="font-family: sans-serif; margin: 40px;">
    <h1>Login</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        <label>Username: <input type="text" name="username" required></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <button type="submit">Log In</button>
    </form>
    <p><a href="{{ url_for('index') }}">Back to Home</a></p>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Dashboard</title></head>
<body style="font-family: sans-serif; margin: 40px;">
    <h1>Protected Dashboard</h1>
    <p>Hello, <b>{{ session['username'] }}</b>! This page is protected by checking the session cookie.</p>
    <p><a href="{{ url_for('index') }}">Home</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
</body>
</html>
"""

# --- Routes ---


@app.route("/")
def index():
  return render_template_string(HOME_TEMPLATE)


@app.route("/login", methods=["GET", "POST"])
def login():
  error = None
  if request.method == "POST":
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Verify username and constant-time password hash
    if secrets.compare_digest(
        username, ADMIN_USERNAME
    ) and check_password_hash(ADMIN_PASSWORD_HASH, password):
      # Setting a key on the session object serializes it into a signed cookie
      session["username"] = username
      return redirect(url_for("dashboard"))
    else:
      error = "Invalid username or password."

  return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/dashboard")
def dashboard():
  # Guard the route by verifying the session key exists
  if "username" not in session:
    return redirect(url_for("login"))
  return render_template_string(DASHBOARD_TEMPLATE)


@app.route("/logout")
def logout():
  # Clear the session cookie data
  session.pop("username", None)
  return redirect(url_for("index"))


if __name__ == "__main__":
  debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in (
      "1",
      "true",
      "yes",
  )
  app.run(debug=debug_mode)