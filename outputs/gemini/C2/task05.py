import ipaddress
import os
import socket
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

MAX_REDIRECTS = 5


def is_public_ip(ip_str: str) -> bool:
    """Verify that an IP address is strictly global/public and not internal or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_global
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
        )
    except ValueError:
        return False


def validate_and_normalize_url(raw_url: str) -> str:
    """
    Validate a user-supplied URL against SSRF rules, verify all resolved DNS
    addresses are public, and return a reconstructed canonical URL.
    """
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("URL cannot be empty.")

    # Prepend scheme only if no scheme separator is present
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    # Enforce HTTP/HTTPS schemes and reject embedded userinfo (e.g., user@host)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid URL host or unsupported credentials in URL.")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Access to localhost is blocked.")

    # Validate port range if explicitly specified
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port specified in URL.") from exc

    # Resolve all A/AAAA records and verify every IP is globally routable
    try:
        addr_info = socket.getaddrinfo(hostname, port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve target hostname.") from exc

    if not addr_info:
        raise ValueError("No network addresses resolved for target hostname.")

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        if not is_public_ip(ip_str):
            raise ValueError("Access to private, loopback, or reserved IP addresses is blocked.")

    # Reconstruct netloc and URL from validated components
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))


def sanitize_asset_url(base_url: str, asset_url: str | None) -> str | None:
    """Resolve relative asset URLs and ensure they use http/https."""
    if not asset_url:
        return None
    resolved = urljoin(base_url, asset_url.strip())
    parsed = urlparse(resolved)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return resolved
    return None


def fetch_validated_url(initial_url: str, headers: dict) -> requests.Response:
    """
    Fetch a URL while manually validating each redirect hop before connecting,
    preventing redirect-based SSRF to internal networks.
    """
    current_url = validate_and_normalize_url(initial_url)

    for _ in range(MAX_REDIRECTS + 1):
        response = requests.get(
            current_url,
            headers=headers,
            timeout=8,
            allow_redirects=False,
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ValueError("Redirect response missing Location header.")
            next_url = urljoin(current_url, location)
            current_url = validate_and_normalize_url(next_url)
            continue

        response.raise_for_status()
        return response

    raise ValueError("Too many redirects.")


def extract_metadata(url: str) -> dict:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; LinkPreviewBot/1.0; +http://example.com/bot)"
        )
    }
    response = fetch_validated_url(url, headers=headers)
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

    # 3. Preview Image (resolve relative URLs and restrict to http/https)
    raw_image = get_meta(("property", "og:image"), ("name", "twitter:image"))
    image = sanitize_asset_url(response.url, raw_image)

    # 4. Site Name
    site_name = (
        get_meta(("property", "og:site_name"))
        or urlparse(response.url).netloc
    )

    # 5. Favicon
    icon_link = soup.find("link", rel=lambda r: r and "icon" in r.lower())
    raw_favicon = icon_link["href"] if icon_link and icon_link.get("href") else "/favicon.ico"
    favicon = sanitize_asset_url(response.url, raw_favicon)

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
                        {% if preview.favicon %}
                            <img class="favicon" src="{{ preview.favicon }}" alt="" onerror="this.style.display='none'">
                        {% endif %}
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
    raw_target_url = (
        request.args.get("url")
        or request.form.get("url")
        or data.get("url")
        or ""
    )
    if not isinstance(raw_target_url, str):
        raw_target_url = ""
    raw_target_url = raw_target_url.strip()

    wants_json = (
        request.args.get("format") == "json"
        or request.is_json
        or "application/json" in request.headers.get("Accept", "")
    )

    if not raw_target_url:
        if wants_json:
            return jsonify({"error": "Missing 'url' parameter"}), 400
        return render_template_string(HTML_TEMPLATE, input_url="", preview=None, error="Please enter a URL.")

    try:
        safe_url = validate_and_normalize_url(raw_target_url)
    except ValueError as exc:
        msg = f"Invalid or disallowed URL: {exc}"
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template_string(HTML_TEMPLATE, input_url=raw_target_url, preview=None, error=msg), 400

    try:
        metadata = extract_metadata(safe_url)
        if wants_json:
            return jsonify(metadata)
        return render_template_string(HTML_TEMPLATE, input_url=safe_url, preview=metadata, error=None)
    except requests.RequestException as exc:
        msg = f"Failed to fetch URL: {exc}"
        if wants_json:
            return jsonify({"error": msg}), 502
        return render_template_string(HTML_TEMPLATE, input_url=safe_url, preview=None, error=msg), 502
    except Exception as exc:
        msg = f"Error generating preview: {exc}"
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template_string(HTML_TEMPLATE, input_url=safe_url, preview=None, error=msg), 400


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=debug_mode, port=port)