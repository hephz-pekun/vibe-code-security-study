#!/usr/bin/env python3
"""
Link preview service (single file).

Install:  pip install flask requests beautifulsoup4
Run:      python link_preview.py
Try:      http://127.0.0.1:5000/                      (form)
          http://127.0.0.1:5000/preview?url=https://example.com   (HTML card)
          http://127.0.0.1:5000/api/preview?url=https://example.com (JSON)

Because this server fetches arbitrary URLs on behalf of users, it defends
against SSRF: only http/https on ports 80/443, no credentials in URLs, every
redirect hop is re-validated, and the IP actually connected to must be public
(checked at connect time, which also defeats DNS rebinding).
"""
import ipaddress
import socket
import threading
import time
from urllib.parse import urljoin, urlparse

import requests
import urllib3.util.connection as urllib3_connection
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template_string, request

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
CONNECT_TIMEOUT = 3.05          # seconds
READ_TIMEOUT = 5                # seconds per read
TOTAL_TIMEOUT = 10              # seconds for the whole fetch
MAX_BYTES = 2 * 1024 * 1024     # stop reading after 2 MB (<head> is all we need)
MAX_REDIRECTS = 5
ALLOWED_PORTS = {None, 80, 443}
USER_AGENT = "Mozilla/5.0 (compatible; LinkPreviewBot/1.0)"

app = Flask(__name__)


class PreviewError(Exception):
    """An error that is safe to show to the user."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------
_local = threading.local()
_orig_create_connection = urllib3_connection.create_connection


def _is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _guarded_create_connection(address, *args, **kwargs):
    """Replacement for urllib3's connect that refuses non-public IPs.

    Resolution and connection happen in the same call, so a malicious DNS
    server can't return a public IP for validation and a private one for
    the real connection (DNS rebinding). Only active while our thread-local
    flag is set, so other code in the process is unaffected.
    """
    if not getattr(_local, "guard", False):
        return _orig_create_connection(address, *args, **kwargs)

    host, port = address
    host = host.strip("[]")
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        if not _is_public_ip(info[4][0]):
            raise OSError("Blocked connection to a non-public address")
    return _orig_create_connection((infos[0][4][0], port), *args, **kwargs)


urllib3_connection.create_connection = _guarded_create_connection


def validate_url(url):
    """Cheap up-front checks that give the user a clear error message."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise PreviewError("Only http and https URLs are supported.")
    if not parsed.hostname:
        raise PreviewError("The URL has no hostname.")
    if parsed.username or parsed.password:
        raise PreviewError("URLs with embedded credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError:
        raise PreviewError("The URL has an invalid port.")
    if port not in ALLOWED_PORTS:
        raise PreviewError("Only ports 80 and 443 are allowed.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise PreviewError("Could not resolve that hostname.", 502)
    if not infos or not all(_is_public_ip(i[4][0]) for i in infos):
        raise PreviewError("That address is not allowed.", 403)


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------
def fetch_page(url):
    """Fetch a page safely. Returns (final_url, body_bytes, charset_or_None)."""
    session = requests.Session()
    session.trust_env = False  # ignore proxy env vars that could bypass the guard
    deadline = time.monotonic() + TOTAL_TIMEOUT
    _local.guard = True
    try:
        resp = None
        for _ in range(MAX_REDIRECTS + 1):
            validate_url(url)
            resp = session.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                },
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                stream=True,
                allow_redirects=False,  # we follow manually to re-validate each hop
            )
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                url = urljoin(url, resp.headers["Location"])
                resp.close()
                continue
            break
        else:
            raise PreviewError("Too many redirects.", 502)

        if resp.status_code >= 400:
            raise PreviewError(f"The site responded with HTTP {resp.status_code}.", 502)

        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" not in ctype and "xml" not in ctype:
            raise PreviewError("That URL doesn't point to an HTML page.", 415)

        charset = None
        if "charset=" in ctype:
            charset = ctype.split("charset=")[-1].split(";")[0].strip(" \"'") or None

        chunks, size = [], 0
        for chunk in resp.iter_content(8192):
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BYTES or time.monotonic() > deadline:
                break
        resp.close()
        return url, b"".join(chunks), charset
    except PreviewError:
        raise
    except requests.exceptions.Timeout:
        raise PreviewError("The site took too long to respond.", 504)
    except requests.exceptions.SSLError:
        raise PreviewError("TLS/SSL error while connecting to the site.", 502)
    except requests.exceptions.RequestException:
        raise PreviewError("Could not fetch that URL.", 502)
    finally:
        _local.guard = False
        session.close()


# --------------------------------------------------------------------------
# Metadata extraction
# --------------------------------------------------------------------------
def _http_url_or_none(base, value):
    """Resolve a possibly-relative URL; allow only http(s) (blocks javascript: etc.)."""
    if not value:
        return None
    absolute = urljoin(base, value.strip())
    return absolute if urlparse(absolute).scheme in ("http", "https") else None


def extract_metadata(body, charset, final_url):
    soup = BeautifulSoup(body, "html.parser", from_encoding=charset)

    def meta(*names):
        for name in names:
            tag = soup.find("meta", attrs={"property": name}) or soup.find(
                "meta", attrs={"name": name}
            )
            if tag and tag.get("content", "").strip():
                return tag["content"].strip()
        return None

    title = meta("og:title", "twitter:title")
    if not title and soup.title and soup.title.string:
        title = soup.title.string.strip()

    description = meta("og:description", "twitter:description", "description")
    if description and len(description) > 300:
        description = description[:297].rstrip() + "..."

    image = _http_url_or_none(final_url, meta("og:image", "twitter:image"))
    site_name = meta("og:site_name") or urlparse(final_url).hostname

    canonical = None
    favicon = None
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if rel == "canonical" and not canonical:
            canonical = _http_url_or_none(final_url, link.get("href"))
        if "icon" in rel and not favicon:
            favicon = _http_url_or_none(final_url, link.get("href"))
    if not favicon:
        p = urlparse(final_url)
        favicon = f"{p.scheme}://{p.netloc}/favicon.ico"

    return {
        "url": canonical or final_url,
        "final_url": final_url,
        "title": title,
        "description": description,
        "image": image,
        "site_name": site_name,
        "favicon": favicon,
    }


def build_preview(raw_url):
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise PreviewError("Missing 'url' parameter.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    final_url, body, charset = fetch_page(raw_url)
    return extract_metadata(body, charset, final_url)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link preview</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; }
  form { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
  input[type=text] { flex: 1; padding: .6rem .8rem; font-size: 1rem; border: 1px solid #bbb; border-radius: 8px; }
  button { padding: .6rem 1.1rem; font-size: 1rem; border: 0; border-radius: 8px; background: #2563eb; color: #fff; cursor: pointer; }
  .card { border: 1px solid #ddd; border-radius: 12px; overflow: hidden; text-decoration: none; color: inherit; display: block; }
  .card img.hero { width: 100%; max-height: 320px; object-fit: cover; display: block; background: #eee; }
  .body { padding: 1rem 1.2rem; }
  .site { display: flex; align-items: center; gap: .4rem; font-size: .85rem; color: #666; margin-bottom: .4rem; }
  .site img { width: 16px; height: 16px; }
  h2 { margin: 0 0 .4rem; font-size: 1.2rem; }
  p { margin: 0; color: #444; line-height: 1.4; }
  .error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: .8rem 1rem; border-radius: 8px; }
</style>
</head>
<body>
  <h1>Link preview</h1>
  <form action="/preview" method="get">
    <input type="text" name="url" placeholder="https://example.com" value="{{ url or '' }}" required>
    <button type="submit">Preview</button>
  </form>

  {% if error %}
    <div class="error">{{ error }}</div>
  {% elif preview %}
    <a class="card" href="{{ preview.url }}" target="_blank" rel="noopener noreferrer nofollow">
      {% if preview.image %}
        <img class="hero" src="{{ preview.image }}" alt="" referrerpolicy="no-referrer" loading="lazy">
      {% endif %}
      <div class="body">
        <div class="site">
          <img src="{{ preview.favicon }}" alt="" referrerpolicy="no-referrer">
          <span>{{ preview.site_name }}</span>
        </div>
        <h2>{{ preview.title or preview.url }}</h2>
        {% if preview.description %}<p>{{ preview.description }}</p>{% endif %}
      </div>
    </a>
  {% endif %}
</body>
</html>
"""


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src http: https: data:; "
        "style-src 'unsafe-inline'; form-action 'self'"
    )
    return resp


@app.get("/")
def index():
    return render_template_string(PAGE, url=None, preview=None, error=None)


@app.get("/preview")
def preview_html():
    url = request.args.get("url", "")
    try:
        data = build_preview(url)
        return render_template_string(PAGE, url=url, preview=data, error=None)
    except PreviewError as e:
        return render_template_string(PAGE, url=url, preview=None, error=e.message), e.status


@app.get("/api/preview")
def preview_json():
    try:
        return jsonify(build_preview(request.args.get("url", "")))
    except PreviewError as e:
        return jsonify(error=e.message), e.status


if __name__ == "__main__":
    # Don't use debug=True in production; use a real WSGI server (e.g. gunicorn).
    app.run(host="127.0.0.1", port=5000)