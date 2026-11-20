from flask import Flask, request, jsonify
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import ipaddress
import socket

app = Flask(__name__)

# Optional: set a custom User-Agent so more sites respond normally.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FlaskPreviewBot/1.0)"
}

# Allowlist of hosts that may be fetched.
# Replace/add approved domains as needed.
ALLOWED_HOSTS = {
    "example.com",
    "www.example.com",
}


def is_public_hostname(hostname: str) -> bool:
    """
    Prevent access to localhost, private networks, and other
    non-public addresses that could be abused for SSRF.
    """
    try:
        addresses = socket.getaddrinfo(hostname, None)

        for addr in addresses:
            ip = ipaddress.ip_address(addr[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
            ):
                return False

        return True
    except Exception:
        return False


def is_allowed_url(url: str) -> bool:
    """
    Validate URL scheme and host against an allowlist
    to mitigate SSRF.
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        if hostname not in ALLOWED_HOSTS:
            return False

        if not is_public_hostname(hostname):
            return False

        return True

    except Exception:
        return False


@app.route("/preview", methods=["GET"])
def preview():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    if not is_allowed_url(url):
        return jsonify({"error": "URL is not permitted"}), 400

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10,
            allow_redirects=False,  # Prevent redirect bypasses
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        description = ""
        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag:
            description = desc_tag.get("content", "").strip()

        if not description:
            og_desc = soup.find(
                "meta",
                attrs={"property": "og:description"}
            )
            if og_desc:
                description = og_desc.get("content", "").strip()

        image = ""
        og_image = soup.find(
            "meta",
            attrs={"property": "og:image"}
        )
        if og_image:
            image = og_image.get("content", "").strip()

        return jsonify({
            "title": title,
            "description": description,
            "image": image
        })

    except requests.RequestException:
        return jsonify({
            "error": "Failed to retrieve preview information"
        }), 500


if __name__ == "__main__":
    # Do not enable debug mode in production.
    app.run(host="0.0.0.0", port=5000, debug=False)