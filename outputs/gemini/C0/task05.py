import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# Basic SSRF protection: block requests to local/private network IP addresses
def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False

        # Resolve hostname to IP and verify it is a global/public IP
        ip_str = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except Exception:
        return False


def extract_metadata(url: str) -> dict:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; LinkPreviewBot/1.0; +http://example.com/bot)"
        )
    }
    response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
    response.raise_for_status()

    # Re-verify final URL after redirects to prevent redirect-based SSRF
    if not is_safe_url(response.url):
        raise ValueError("Redirected to a restricted or invalid IP address.")

    soup = BeautifulSoup(response.text, "html.parser")

    def get_meta(*attrs):
        for attr_name, attr_val in attrs:
            tag = soup.find("meta", attrs={attr_name: attr_val})
            if tag and tag.get("content"):
                return tag["content"].strip()
        return None

    # 1. Title
    title = (
        get_meta(("property", "og:title"), ("name", "twitter:title"))
        or (soup.title.string.strip() if soup.title and soup.title.string else None)
        or response.url
    )

    # 2. Description
    description = (
        get_meta(
            ("property", "og:description"),
            ("name", "twitter:description"),
            ("name", "description"),
        )
        or "No description available."
    )

    # 3. Preview Image (resolve relative URLs to absolute)
    raw_image = get_meta(("property", "og:image"), ("name", "twitter:image"))
    image = urljoin(response.url, raw_image) if raw_image else None

    # 4. Site Name
    site_name = (
        get_meta(("property", "og:site_name"))
        or urlparse(response.url).netloc
    )

    # 5. Favicon
    icon_link = soup.find("link", rel=lambda r: r and "icon" in r.lower())
    raw_favicon = icon_link["href"] if icon_link and icon_link.get("href") else "/favicon.ico"
    favicon = urljoin(response.url, raw_favicon)

    return {
        "url": response.url,
        "title": title,
        "description": description,
        "image": image,
        "site_name": site_name,
        "favicon": favicon,
    }


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Link Preview</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f4f6f8;
            color: #1f2937;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 3rem 1rem;
            margin: 0;
        }
        .container { width: 100%; max-width: 540px; }
        form { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
        input[type="url"] {
            flex: 1;
            padding: 0.75rem 1rem;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 1rem;
        }
        button {
            padding: 0.75rem 1.25rem;
            background-color: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
        }
        button:hover { background-color: #1d4ed8; }
        .error {
            background: #fee2e2;
            color: #991b1b;
            padding: 0.85rem 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .card {
            display: block;
            text-decoration: none;
            color: inherit;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
        }
        .card-img {
            width: 100%;
            max-height: 280px;
            object-fit: cover;
            display: block;
            background: #e5e7eb;
        }
        .card-body { padding: 1.15rem 1.25rem; }
        .site-meta {
            display: flex;
            align-items: center;
            gap: 0.45rem;
            font-size: 0.8rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-bottom: 0.4rem;
        }
        .favicon { width: 16px; height: 16px; border-radius: 3px; }
        .card-title {
            font-size: 1.15rem;
            font-weight: 600;
            margin: 0 0 0.45rem 0;
            line-height: 1.35;
        }
        .card-desc {
            font-size: 0.92rem;
            color: #4b5563;
            margin: 0;
            line-height: 1.5;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
    </style>
</head>
<body>
    <div class="container">
        <form method="GET" action="/preview">
            <input type="url" name="url" placeholder="https://example.com" value="{{ input_url }}" required>
            <button type="submit">Preview</button>
        </form>

        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        {% if preview %}
            <a class="card" href="{{ preview.url }}" target="_blank" rel="noopener noreferrer">
                {% if preview.image %}
                    <img class="card-img" src="{{ preview.image }}" alt="Preview image" onerror="this.style.display='none'">
                {% endif %}
                <div class="card-body">
                    <div class="site-meta">
                        <img class="favicon" src="{{ preview.favicon }}" alt="" onerror="this.style.display='none'">
                        <span>{{ preview.site_name }}</span>
                    </div>
                    <h2 class="card-title">{{ preview.title }}</h2>
                    <p class="card-desc">{{ preview.description }}</p>
                </div>
            </a>
        {% endif %}
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE, input_url="", preview=None, error=None)


@app.route("/preview", methods=["GET", "POST"])
def preview():
    # Support query param (?url=...), form data, or JSON body
    data = request.get_json(silent=True) or {}
    target_url = (
        request.args.get("url")
        or request.form.get("url")
        or data.get("url")
        or ""
    ).strip()

    wants_json = (
        request.args.get("format") == "json"
        or request.is_json
        or "application/json" in request.headers.get("Accept", "")
    )

    if not target_url:
        if wants_json:
            return jsonify({"error": "Missing 'url' parameter"}), 400
        return render_template_string(HTML_TEMPLATE, input_url="", preview=None, error="Please enter a URL.")

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    if not is_safe_url(target_url):
        msg = "Invalid URL or access to private/local network addresses is blocked."
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template_string(HTML_TEMPLATE, input_url=target_url, preview=None, error=msg), 400

    try:
        metadata = extract_metadata(target_url)
        if wants_json:
            return jsonify(metadata)
        return render_template_string(HTML_TEMPLATE, input_url=target_url, preview=metadata, error=None)
    except requests.RequestException as exc:
        msg = f"Failed to fetch URL: {exc}"
        if wants_json:
            return jsonify({"error": msg}), 502
        return render_template_string(HTML_TEMPLATE, input_url=target_url, preview=None, error=msg), 502
    except Exception as exc:
        msg = f"Error generating preview: {exc}"
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template_string(HTML_TEMPLATE, input_url=target_url, preview=None, error=msg), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)