"""
Simple CSV User Importer (Flask)

Features:
- Admin uploads a CSV file
- Validates required fields
- Prevents duplicate emails
- Stores users in SQLite
- Displays import results

Required CSV format:

name,email,role
John Doe,john@example.com,user
Jane Smith,jane@example.com,admin

Install:
    pip install flask

Run:
    python csv_user_importer.py

Open:
    http://127.0.0.1:5000
"""

import csv
import io
import sqlite3
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)
DATABASE = "users.db"


# ----------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------
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
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# ----------------------------------------------------------------------
# User Operations
# ----------------------------------------------------------------------
def user_exists(email):
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email.lower().strip(),)
    ).fetchone()
    conn.close()
    return row is not None


def create_user(name, email, role):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO users (name, email, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            name.strip(),
            email.lower().strip(),
            role.strip(),
            datetime.utcnow().isoformat()
        )
    )
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_db()
    users = conn.execute(
        """
        SELECT id, name, email, role, created_at
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()
    conn.close()
    return users


# ----------------------------------------------------------------------
# CSV Import Logic
# ----------------------------------------------------------------------
def import_csv(file_storage):
    required_fields = {"name", "email", "role"}

    content = file_storage.read().decode("utf-8")
    csv_file = io.StringIO(content)

    reader = csv.DictReader(csv_file)

    if not reader.fieldnames:
        return {
            "success": 0,
            "failed": ["CSV file is empty."]
        }

    headers = {h.strip().lower() for h in reader.fieldnames}

    missing = required_fields - headers
    if missing:
        return {
            "success": 0,
            "failed": [
                f"Missing required columns: {', '.join(sorted(missing))}"
            ]
        }

    success_count = 0
    failed_rows = []

    for line_number, row in enumerate(reader, start=2):
        try:
            name = (row.get("name") or "").strip()
            email = (row.get("email") or "").strip().lower()
            role = (row.get("role") or "").strip()

            if not name:
                raise ValueError("Missing name")

            if not email:
                raise ValueError("Missing email")

            if "@" not in email:
                raise ValueError("Invalid email")

            if not role:
                raise ValueError("Missing role")

            if user_exists(email):
                raise ValueError("User already exists")

            create_user(name, email, role)
            success_count += 1

        except Exception as exc:
            failed_rows.append(
                f"Row {line_number}: {str(exc)}"
            )

    return {
        "success": success_count,
        "failed": failed_rows
    }


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CSV User Importer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 30px auto;
            padding: 20px;
        }

        h1 {
            color: #333;
        }

        .box {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
        }

        th {
            background: #f5f5f5;
        }

        .success {
            color: green;
        }

        .error {
            color: red;
        }

        button {
            padding: 8px 15px;
            cursor: pointer;
        }
    </style>
</head>
<body>

<h1>Admin User Import</h1>

<div class="box">
    <form method="post" action="/import" enctype="multipart/form-data">
        <p>Select CSV file:</p>
        <input type="file" name="csv_file" accept=".csv" required>
        <button type="submit">Import Users</button>
    </form>
</div>

{% if results %}
<div class="box">
    <h2>Import Results</h2>

    <p class="success">
        Successfully imported: {{ results.success }}
    </p>

    {% if results.failed %}
    <h3>Errors</h3>
    <ul>
        {% for item in results.failed %}
        <li class="error">{{ item }}</li>
        {% endfor %}
    </ul>
    {% endif %}
</div>
{% endif %}

<div class="box">
    <h2>Users</h2>

    <table>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Created</th>
        </tr>

        {% for user in users %}
        <tr>
            <td>{{ user["id"] }}</td>
            <td>{{ user["name"] }}</td>
            <td>{{ user["email"] }}</td>
            <td>{{ user["role"] }}</td>
            <td>{{ user["created_at"] }}</td>
        </tr>
        {% endfor %}
    </table>
</div>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(
        HTML,
        users=get_all_users(),
        results=None
    )


@app.route("/import", methods=["POST"])
def upload_csv():
    file = request.files.get("csv_file")

    if not file:
        return redirect(url_for("index"))

    results = import_csv(file)

    return render_template_string(
        HTML,
        users=get_all_users(),
        results=results
    )


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)