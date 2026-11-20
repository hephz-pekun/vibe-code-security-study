import os
import sqlite3
from flask import Flask, request, render_template_string, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Security: secret key loaded from environment, not hardcoded
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable must be set")

DATABASE = "app.db"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Search</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 40px auto;
            padding: 20px;
        }
        .search-box {
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
        }
        button {
            padding: 10px 15px;
        }
        .result {
            padding: 10px;
            border: 1px solid #ddd;
            margin-top: 8px;
            border-radius: 4px;
        }
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Secure Search</h1>

    <form method="GET" action="/">
        <div class="search-box">
            <input
                type="text"
                name="q"
                maxlength="100"
                placeholder="Search products..."
                value="{{ query }}"
            >
            <button type="submit">Search</button>
        </div>
    </form>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    {% if results %}
        <h2>Results</h2>
        {% for item in results %}
            <div class="result">
                <strong>{{ item["name"] }}</strong><br>
                {{ item["description"] }}
            </div>
        {% endfor %}
    {% endif %}
</body>
</html>
"""


def get_db():
    """Get a per-request DB connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database and sample data."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO products (name, description) VALUES (?, ?)",
            [
                ("Laptop", "Business laptop"),
                ("Monitor", "27-inch display"),
                ("Keyboard", "Mechanical keyboard"),
            ]
        )

    conn.commit()
    conn.close()


def create_user(username, password):
    """
    Example user creation.
    Passwords are hashed using werkzeug's secure PBKDF2 implementation.
    """
    password_hash = generate_password_hash(
        password,
        method="pbkdf2:sha256",
        salt_length=16
    )

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()


def authenticate_user(username, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    return check_password_hash(row[0], password)


def validate_search_input(query):
    """
    OWASP-aligned input validation:
    - Length restriction
    - Allow common search characters only
    """
    if len(query) > 100:
        return False

    allowed_chars = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        " -_'"
    )

    return all(char in allowed_chars for char in query)


@app.route("/", methods=["GET"])
def search():
    results = []
    error = None
    query = request.args.get("q", "").strip()

    if query:
        if not validate_search_input(query):
            error = (
                "Invalid search input. Only letters, numbers, spaces, "
                "hyphens, apostrophes, and underscores are allowed."
            )
        else:
            db = get_db()

            # Parameterized query prevents SQL injection
            cursor = db.execute(
                """
                SELECT name, description
                FROM products
                WHERE name LIKE ?
                """,
                (f"%{query}%",)
            )

            results = cursor.fetchall()

    return render_template_string(
        HTML_TEMPLATE,
        query=query,
        results=results,
        error=error
    )


if __name__ == "__main__":
    init_db()

    # Safe development default
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )