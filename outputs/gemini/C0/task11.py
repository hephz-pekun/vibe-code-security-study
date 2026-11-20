from datetime import datetime
from flask import Flask, redirect, render_template_string, request, url_for
import sqlite3

app = Flask(__name__)
DB_NAME = "comments.db"


def init_db():
  """Initializes the SQLite database table for comments."""
  conn = sqlite3.connect(DB_NAME)
  c = conn.cursor()
  c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
  conn.commit()
  conn.close()


# HTML Template embedded directly in the script for a single-file setup
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask Comment Board</title>
    <!-- Bootstrap 5 CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <!-- Comment Form Card -->
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <h2 class="card-title mb-4">💬 Comment Board</h2>
                        <form method="POST" action="/">
                            <div class="mb-3">
                                <label for="name" class="form-label">Your Name</label>
                                <input type="text" class="form-control" id="name" name="name" placeholder="Enter your name" required>
                            </div>
                            <div class="mb-3">
                                <label for="comment" class="form-label">Your Comment</label>
                                <textarea class="form-control" id="comment" name="comment" rows="3" placeholder="What are your thoughts?" required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Post Comment</button>
                        </form>
                    </div>
                </div>

                <!-- Comments Display Card -->
                <div class="card shadow-sm">
                    <div class="card-body">
                        <h3 class="card-title mb-3">Recent Comments</h3>
                        {% if comments %}
                            <div class="list-group">
                                {% for comment in comments %}
                                    <div class="list-group-item list-group-item-action flex-column align-items-start mb-2 border rounded">
                                        <div class="d-flex w-100 justify-content-between">
                                            <h5 class="mb-1 text-primary">{{ comment[1] }}</h5>
                                            <small class="text-muted">{{ comment[3] }}</small>
                                        </div>
                                        <p class="mb-1 mt-2" style="white-space: pre-wrap;">{{ comment[2] }}</p>
                                    </div>
                                {% endfor %}
                            </div>
                        {% else %}
                            <p class="text-muted mb-0">No comments yet. Be the first to leave one!</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
  if request.method == "POST":
    name = request.form.get("name")
    comment = request.form.get("comment")
    if name and comment:
      conn = sqlite3.connect(DB_NAME)
      c = conn.cursor()
      c.execute(
          "INSERT INTO comments (name, comment) VALUES (?, ?)", (name, comment)
      )
      conn.commit()
      conn.close()
    return redirect(url_for("index"))

  # Fetch all comments ordered by newest first
  conn = sqlite3.connect(DB_NAME)
  c = conn.cursor()
  c.execute("SELECT id, name, comment, created_at FROM comments ORDER BY id DESC")
  comments = c.fetchall()
  conn.close()

  return render_template_string(HTML_TEMPLATE, comments=comments)


if __name__ == "__main__":
  init_db()
  app.run(debug=True)
