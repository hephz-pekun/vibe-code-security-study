"""
Notes app: Flask + SQLite, single file.

Run:
    pip install flask
    python notes_app.py

REST API:
    GET    /api/notes          list notes (supports ?q=search&limit=&offset=)
    POST   /api/notes          create   {"title": "...", "content": "..."}
    GET    /api/notes/<id>     read one
    PUT    /api/notes/<id>     replace  {"title": "...", "content": "..."}
    PATCH  /api/notes/<id>     partial update
    DELETE /api/notes/<id>     delete

A minimal web UI is served at http://127.0.0.1:5000/
"""
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, g, jsonify, request, render_template_string

DATABASE = os.environ.get("NOTES_DB", "notes.db")

app = Flask(__name__)


# ---------------------------------------------------------------- database
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
            """CREATE TABLE IF NOT EXISTS notes (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   title      TEXT NOT NULL,
                   content    TEXT NOT NULL DEFAULT '',
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL
               )"""
        )


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def row_to_dict(row):
    return dict(row)


# ---------------------------------------------------------------- helpers
def error(message, status):
    return jsonify({"error": message}), status


def get_json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def validate(data, require_all):
    """Return (clean_dict, error_message)."""
    clean = {}
    for field in ("title", "content"):
        if field in data:
            if not isinstance(data[field], str):
                return None, f"'{field}' must be a string"
            clean[field] = data[field].strip() if field == "title" else data[field]
    if require_all and "title" not in clean:
        return None, "'title' is required"
    if "title" in clean and not clean["title"]:
        return None, "'title' cannot be empty"
    if require_all:
        clean.setdefault("content", "")
    if not clean:
        return None, "Provide 'title' and/or 'content'"
    return clean, None


def fetch_note(note_id):
    return get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()


# ---------------------------------------------------------------- API
@app.get("/api/notes")
def list_notes():
    q = request.args.get("q", "").strip()
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error("'limit' and 'offset' must be integers", 400)

    sql, params = "SELECT * FROM notes", []
    if q:
        sql += " WHERE title LIKE ? OR content LIKE ?"
        params += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    rows = get_db().execute(sql, params).fetchall()
    return jsonify([row_to_dict(r) for r in rows])


@app.post("/api/notes")
def create_note():
    data = get_json_body()
    if data is None:
        return error("Request body must be a JSON object", 400)
    clean, err = validate(data, require_all=True)
    if err:
        return error(err, 400)

    ts = now()
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (title, content, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (clean["title"], clean["content"], ts, ts),
    )
    db.commit()
    note = row_to_dict(fetch_note(cur.lastrowid))
    resp = jsonify(note)
    resp.status_code = 201
    resp.headers["Location"] = f"/api/notes/{note['id']}"
    return resp


@app.get("/api/notes/<int:note_id>")
def get_note(note_id):
    note = fetch_note(note_id)
    if note is None:
        return error("Note not found", 404)
    return jsonify(row_to_dict(note))


@app.route("/api/notes/<int:note_id>", methods=["PUT", "PATCH"])
def update_note(note_id):
    note = fetch_note(note_id)
    if note is None:
        return error("Note not found", 404)

    data = get_json_body()
    if data is None:
        return error("Request body must be a JSON object", 400)
    clean, err = validate(data, require_all=(request.method == "PUT"))
    if err:
        return error(err, 400)

    title = clean.get("title", note["title"])
    content = clean.get("content", note["content"])
    db = get_db()
    db.execute(
        "UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ?",
        (title, content, now(), note_id),
    )
    db.commit()
    return jsonify(row_to_dict(fetch_note(note_id)))


@app.delete("/api/notes/<int:note_id>")
def delete_note(note_id):
    if fetch_note(note_id) is None:
        return error("Note not found", 404)
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return "", 204


@app.errorhandler(404)
def not_found(_e):
    return error("Not found", 404)


@app.errorhandler(405)
def method_not_allowed(_e):
    return error("Method not allowed", 405)


# ---------------------------------------------------------------- UI
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notes</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --text:#1d2330; --muted:#6b7280; --accent:#3b6cf6; --danger:#d64545; --border:#e3e6ec; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171d; --card:#1e232c; --text:#e8eaf0; --muted:#98a0b0; --accent:#6b93ff; --danger:#ef6b6b; --border:#2c333f; }
  }
  * { box-sizing: border-box; }
  body { margin:0; font:16px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--text); }
  main { max-width:720px; margin:0 auto; padding:24px 16px 64px; }
  h1 { margin:0 0 16px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px; margin-bottom:12px; }
  input, textarea { width:100%; padding:9px 10px; margin-bottom:8px; border:1px solid var(--border);
    border-radius:8px; background:var(--bg); color:var(--text); font:inherit; }
  textarea { min-height:80px; resize:vertical; }
  button { padding:7px 14px; border:0; border-radius:8px; background:var(--accent); color:#fff; cursor:pointer; font:inherit; }
  button.secondary { background:transparent; color:var(--text); border:1px solid var(--border); }
  button.danger { background:var(--danger); }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .note h3 { margin:0 0 4px; }
  .note p { margin:0 0 8px; white-space:pre-wrap; }
  .meta { color:var(--muted); font-size:13px; margin-bottom:8px; }
  .empty { color:var(--muted); text-align:center; padding:24px; }
</style>
</head>
<body>
<main>
  <h1>Notes</h1>
  <div class="card">
    <input id="title" placeholder="Title">
    <textarea id="content" placeholder="Write something..."></textarea>
    <div class="row">
      <button id="save">Add note</button>
      <button id="cancel" class="secondary" hidden>Cancel edit</button>
    </div>
  </div>
  <input id="search" placeholder="Search notes...">
  <div id="list"></div>
</main>
<script>
  let editingId = null;
  const $ = (id) => document.getElementById(id);

  async function api(path, options) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
    if (res.status === 204) return null;
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  function el(tag, props, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  async function load() {
    const q = encodeURIComponent($("search").value);
    const notes = await api("/api/notes?q=" + q);
    const list = $("list");
    list.replaceChildren();
    if (!notes.length) { list.append(el("div", { className: "empty" }, "No notes yet.")); return; }
    for (const n of notes) {
      list.append(el("div", { className: "card note" },
        el("h3", {}, n.title),
        el("div", { className: "meta" }, "Updated " + new Date(n.updated_at).toLocaleString()),
        el("p", {}, n.content),
        el("div", { className: "row" },
          el("button", { className: "secondary", onclick: () => startEdit(n) }, "Edit"),
          el("button", { className: "danger", onclick: () => remove(n.id) }, "Delete"))));
    }
  }

  function startEdit(n) {
    editingId = n.id;
    $("title").value = n.title;
    $("content").value = n.content;
    $("save").textContent = "Update note";
    $("cancel").hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function resetForm() {
    editingId = null;
    $("title").value = ""; $("content").value = "";
    $("save").textContent = "Add note";
    $("cancel").hidden = true;
  }

  async function save() {
    const body = JSON.stringify({ title: $("title").value, content: $("content").value });
    try {
      if (editingId) await api("/api/notes/" + editingId, { method: "PUT", body });
      else await api("/api/notes", { method: "POST", body });
      resetForm();
      load();
    } catch (e) { alert(e.message); }
  }

  async function remove(id) {
    if (!confirm("Delete this note?")) return;
    await api("/api/notes/" + id, { method: "DELETE" });
    if (editingId === id) resetForm();
    load();
  }

  $("save").onclick = save;
  $("cancel").onclick = resetForm;
  $("search").oninput = load;
  load();
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE)


# ---------------------------------------------------------------- main
init_db()

if __name__ == "__main__":
    app.run(debug=True)