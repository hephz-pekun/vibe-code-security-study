"""
Simple Flask comment board.

Run:
    pip install flask
    python comment_board.py
Then open http://127.0.0.1:5000
"""

import os
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, session, url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "comments.db")
MAX_NAME = 50
MAX_COMMENT = 1000
PER_PAGE = 20


# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS comments (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   author TEXT NOT NULL,
                   body TEXT NOT NULL,
                   created_at TEXT NOT NULL
               )"""
        )


# ---------- CSRF protection (lightweight) ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token.")


# ---------- Template ----------
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Comment Board</title>
<style>
  :root { --bg:#f5f6f8; --card:#fff; --text:#1d2330; --muted:#6b7280;
          --accent:#3b6ef5; --border:#e2e5ea; --err:#b42318; --ok:#17803d; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171d; --card:#1e232c; --text:#e8eaee; --muted:#9aa3b2;
            --accent:#6c93ff; --border:#2d3440; --err:#ff8a80; --ok:#6fd694; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height:1.5; }
  main { max-width: 680px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { margin: 0 0 4px; }
  .sub { color: var(--muted); margin: 0 0 24px; }
  .card { background: var(--card); border: 1px solid var(--border);
          border-radius: 10px; padding: 16px; margin-bottom: 14px; }
  label { display:block; font-weight:600; margin: 0 0 4px; font-size:.9rem; }
  input[type=text], textarea {
    width:100%; padding:10px; border:1px solid var(--border); border-radius:8px;
    background: var(--bg); color: var(--text); font: inherit; margin-bottom: 12px; }
  textarea { min-height: 90px; resize: vertical; }
  button { background: var(--accent); color:#fff; border:0; border-radius:8px;
           padding:10px 18px; font: inherit; font-weight:600; cursor:pointer; }
  button:hover { filter: brightness(1.08); }
  .flash { padding:10px 14px; border-radius:8px; margin-bottom:14px; border:1px solid var(--border); }
  .flash.error { color: var(--err); }
  .flash.success { color: var(--ok); }
  .meta { display:flex; justify-content:space-between; gap:8px; color:var(--muted); font-size:.85rem; margin-bottom:6px; }
  .author { color: var(--text); font-weight:700; }
  .body { white-space: pre-wrap; word-wrap: break-word; overflow-wrap: anywhere; }
  .pager { display:flex; justify-content:space-between; margin-top:8px; }
  .pager a { color: var(--accent); text-decoration:none; font-weight:600; }
  .empty { text-align:center; color:var(--muted); }
</style>
</head>
<body>
<main>
  <h1>Comment Board</h1>
  <p class="sub">{{ total }} comment{{ '' if total == 1 else 's' }}</p>

  {% for category, message in get_flashed_messages(with_categories=true) %}
    <div class="flash {{ category }}">{{ message }}</div>
  {% endfor %}

  <form method="post" action="{{ url_for('post_comment') }}" class="card">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <label for="author">Name</label>
    <input type="text" id="author" name="author" maxlength="{{ max_name }}"
           value="{{ form_author }}" placeholder="Your name" required>
    <label for="body">Comment</label>
    <textarea id="body" name="body" maxlength="{{ max_comment }}"
              placeholder="Say something..." required>{{ form_body }}</textarea>
    <button type="submit">Post comment</button>
  </form>

  {% if comments %}
    {% for c in comments %}
      <article class="card">
        <div class="meta">
          <span class="author">{{ c['author'] }}</span>
          <time>{{ c['created_at'] }}</time>
        </div>
        <div class="body">{{ c['body'] }}</div>
      </article>
    {% endfor %}
    <div class="pager">
      <span>{% if page > 1 %}<a href="{{ url_for('index', page=page-1) }}">&larr; Newer</a>{% endif %}</span>
      <span>{% if has_next %}<a href="{{ url_for('index', page=page+1) }}">Older &rarr;</a>{% endif %}</span>
    </div>
  {% else %}
    <p class="empty">No comments yet. Be the first!</p>
  {% endif %}
</main>
</body>
</html>
"""


# ---------- Routes ----------
@app.get("/")
def index():
    page = max(request.args.get("page", 1, type=int), 1)
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
    rows = db.execute(
        "SELECT author, body, created_at FROM comments "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        (PER_PAGE + 1, (page - 1) * PER_PAGE),
    ).fetchall()
    return render_template_string(
        PAGE,
        comments=rows[:PER_PAGE],
        has_next=len(rows) > PER_PAGE,
        page=page,
        total=total,
        max_name=MAX_NAME,
        max_comment=MAX_COMMENT,
        form_author=session.pop("draft_author", ""),
        form_body=session.pop("draft_body", ""),
    )


@app.post("/comment")
def post_comment():
    author = request.form.get("author", "").strip()
    body = request.form.get("body", "").strip()

    error = None
    if not author or not body:
        error = "Name and comment are both required."
    elif len(author) > MAX_NAME:
        error = f"Name must be {MAX_NAME} characters or fewer."
    elif len(body) > MAX_COMMENT:
        error = f"Comment must be {MAX_COMMENT} characters or fewer."

    if error:
        # Keep what the user typed so they don't lose it
        session["draft_author"] = author[:MAX_NAME]
        session["draft_body"] = body[:MAX_COMMENT]
        flash(error, "error")
        return redirect(url_for("index"))

    db = get_db()
    db.execute(
        "INSERT INTO comments (author, body, created_at) VALUES (?, ?, ?)",
        (author, body, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
    )
    db.commit()
    flash("Comment posted!", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)