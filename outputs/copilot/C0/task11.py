from flask import Flask, request, redirect, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)

DATABASE = "comments.db"

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Home page
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        comment = request.form.get("comment", "").strip()

        if username and comment:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO comments (username, comment, created_at) VALUES (?, ?, ?)",
                (username, comment, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )

            conn.commit()
            conn.close()

        return redirect("/")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, comment, created_at
        FROM comments
        ORDER BY id DESC
    """)

    comments = cursor.fetchall()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Flask Comment Board</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 40px auto;
                padding: 20px;
                background: #f5f5f5;
            }

            h1 {
                text-align: center;
            }

            form {
                background: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
            }

            input[type="text"],
            textarea {
                width: 100%;
                padding: 10px;
                margin-top: 5px;
                margin-bottom: 15px;
                border: 1px solid #ccc;
                border-radius: 4px;
                box-sizing: border-box;
            }

            button {
                background: #007bff;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
            }

            button:hover {
                background: #0056b3;
            }

            .comment {
                background: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 10px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }

            .meta {
                color: #666;
                font-size: 0.9em;
                margin-bottom: 8px;
            }

            .username {
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Comment Board</h1>

        <form method="POST">
            <label>Username</label>
            <input type="text" name="username" required>

            <label>Comment</label>
            <textarea name="comment" rows="4" required></textarea>

            <button type="submit">Post Comment</button>
        </form>

        <h2>Recent Comments</h2>

        {% for username, comment, created_at in comments %}
            <div class="comment">
                <div class="meta">
                    <span class="username">{{ username }}</span>
                    • {{ created_at }}
                </div>
                <div>{{ comment }}</div>
            </div>
        {% else %}
            <p>No comments yet.</p>
        {% endfor %}
    </body>
    </html>
    """

    return render_template_string(html, comments=comments)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)