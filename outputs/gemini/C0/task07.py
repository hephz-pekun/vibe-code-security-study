from flask import Flask, request, render_template_string

app = Flask(__name__)

# Sample dataset to search through
ITEMS = [
    {"id": 1, "title": "Python Programming", "category": "Language", "description": "A high-level, general-purpose programming language."},
    {"id": 2, "title": "Flask Web Framework", "category": "Framework", "description": "A lightweight WSGI web application framework in Python."},
    {"id": 3, "title": "SQLite Database", "category": "Database", "description": "A C-language library that implements a small, fast, self-contained SQL database engine."},
    {"id": 4, "title": "HTML & CSS", "category": "Frontend", "description": "The standard markup language and style sheet language for web pages."},
    {"id": 5, "title": "Jinja2 Templating", "category": "Library", "description": "A modern and designer-friendly templating engine for Python."},
    {"id": 6, "title": "REST API Design", "category": "Architecture", "description": "Architectural style for providing standards between computer systems on the web."},
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask Search</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 700px;
            margin: 40px auto;
            padding: 0 20px;
            background-color: #f9fafb;
            color: #111827;
        }
        h1 {
            margin-bottom: 20px;
        }
        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        input[type="text"] {
            flex: 1;
            padding: 12px 16px;
            font-size: 16px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            outline: none;
        }
        input[type="text"]:focus {
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        button {
            padding: 12px 24px;
            font-size: 16px;
            font-weight: 600;
            color: white;
            background-color: #2563eb;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }
        button:hover {
            background-color: #1d4ed8;
        }
        .result-card {
            background: white;
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            margin-bottom: 12px;
        }
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        .result-title {
            font-size: 18px;
            font-weight: 600;
            margin: 0;
        }
        .badge {
            font-size: 12px;
            background: #e0e7ff;
            color: #1e40af;
            padding: 3px 8px;
            border-radius: 12px;
            font-weight: 500;
        }
        .result-desc {
            margin: 0;
            color: #4b5563;
            font-size: 14px;
        }
        .status {
            color: #6b7280;
            margin-bottom: 16px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <h1>Search Directory</h1>

    <form class="search-form" method="GET" action="/">
        <input type="text" name="q" placeholder="Search by title, category, or description..." value="{{ query }}" autofocus>
        <button type="submit">Search</button>
    </form>

    {% if query %}
        <div class="status">Showing {{ results|length }} result(s) for "<strong>{{ query }}</strong>"</div>
    {% else %}
        <div class="status">Showing all {{ results|length }} items</div>
    {% endif %}

    {% if results %}
        {% for item in results %}
            <div class="result-card">
                <div class="result-header">
                    <h2 class="result-title">{{ item.title }}</h2>
                    <span class="badge">{{ item.category }}</span>
                </div>
                <p class="result-desc">{{ item.description }}</p>
            </div>
        {% endfor %}
    {% else %}
        <p>No matching results found. Try a different search term.</p>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    # Retrieve the search query from URL parameters (?q=...)
    query = request.args.get("q", "").strip()

    if query:
        q_lower = query.lower()
        results = [
            item for item in ITEMS
            if q_lower in item["title"].lower()
            or q_lower in item["category"].lower()
            or q_lower in item["description"].lower()
        ]
    else:
        results = ITEMS

    return render_template_string(HTML_TEMPLATE, query=query, results=results)

if __name__ == "__main__":
    app.run(debug=True)