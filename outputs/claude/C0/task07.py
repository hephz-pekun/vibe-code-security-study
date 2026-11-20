"""
Flask search page.

Run:
    pip install flask
    python app.py
Then open http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, request

app = Flask(__name__)

# Sample data to search. Replace with a database query or API call.
ITEMS = [
    {"title": "Python", "description": "A readable, general-purpose programming language."},
    {"title": "Flask", "description": "A lightweight Python web framework."},
    {"title": "Django", "description": "A batteries-included Python web framework."},
    {"title": "JavaScript", "description": "The programming language of the web browser."},
    {"title": "SQLite", "description": "A small, file-based SQL database engine."},
    {"title": "PostgreSQL", "description": "A powerful open-source relational database."},
    {"title": "Jinja2", "description": "The templating engine used by Flask."},
    {"title": "NumPy", "description": "Fast array computing for Python."},
    {"title": "Pandas", "description": "Data analysis and manipulation library for Python."},
    {"title": "Docker", "description": "Package applications into portable containers."},
]


def search_items(query):
    """Return items whose title or description contains every word in the query."""
    words = query.lower().split()
    results = []
    for item in ITEMS:
        text = f"{item['title']} {item['description']}".lower()
        if all(word in text for word in words):
            results.append(item)
    return results


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Search</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --surface: #ffffff;
      --text: #1d2330;
      --muted: #5f6b7e;
      --border: #d8dce4;
      --accent: #2456d6;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #14171d;
        --surface: #1d222b;
        --text: #e8ebf1;
        --muted: #98a2b3;
        --border: #323a48;
        --accent: #7aa2ff;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 48px 16px;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
    }
    main { max-width: 640px; margin: 0 auto; }
    h1 { font-size: 1.75rem; margin: 0 0 20px; }
    form { display: flex; gap: 8px; }
    input[type="search"] {
      flex: 1;
      padding: 12px 14px;
      font-size: 1rem;
      color: var(--text);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    button {
      padding: 12px 20px;
      font-size: 1rem;
      color: #fff;
      background: var(--accent);
      border: 0;
      border-radius: 8px;
      cursor: pointer;
    }
    input:focus-visible, button:focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    .status { margin: 24px 0 8px; color: var(--muted); }
    ul { list-style: none; margin: 0; padding: 0; }
    li {
      padding: 14px 16px;
      margin-bottom: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    li strong { display: block; }
    li span { color: var(--muted); }
    mark { background: rgba(255, 200, 0, 0.35); color: inherit; border-radius: 2px; }
  </style>
</head>
<body>
  <main>
    <h1>Search</h1>

    <form method="get" action="/" role="search">
      <input type="search" name="q" value="{{ query }}"
             placeholder="Try &quot;python&quot; or &quot;database&quot;"
             aria-label="Search" autofocus>
      <button type="submit">Search</button>
    </form>

    {% if searched %}
      {% if results %}
        <p class="status">{{ results|length }} result{{ '' if results|length == 1 else 's' }} for "{{ query }}"</p>
        <ul>
          {% for item in results %}
            <li>
              <strong>{{ item.title }}</strong>
              <span>{{ item.description }}</span>
            </li>
          {% endfor %}
        </ul>
      {% else %}
        <p class="status">No results for "{{ query }}". Try a different word.</p>
      {% endif %}
    {% else %}
      <p class="status">Type a word above to search.</p>
    {% endif %}
  </main>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    query = request.args.get("q", "").strip()
    searched = bool(query)
    results = search_items(query) if searched else []
    return render_template_string(PAGE, query=query, searched=searched, results=results)


if __name__ == "__main__":
    app.run(debug=True)