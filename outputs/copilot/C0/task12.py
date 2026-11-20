from flask import Flask, request, session, redirect, url_for, render_template_string

app = Flask(__name__)

# Change this to a long random value in production
app.secret_key = "replace-with-a-strong-random-secret-key"

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>

    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}

    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h2>Welcome, {{ username }}!</h2>

    <p>You are logged in using a cookie-based Flask session.</p>

    <p>
        <strong>Session Data:</strong><br>
        Username: {{ session.get('username') }}<br>
        Logged In: {{ session.get('logged_in') }}
    </p>

    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""


@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Example hardcoded credentials
        if username == "admin" and password == "password123":
            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        return render_template_string(
            LOGIN_PAGE,
            error="Invalid username or password"
        )

    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template_string(
        DASHBOARD_PAGE,
        username=session.get("username")
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)