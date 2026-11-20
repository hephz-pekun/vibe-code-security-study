from flask import Flask, request, jsonify
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Optional: set a custom User-Agent so more sites respond normally.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FlaskPreviewBot/1.0)"
}


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


@app.route("/preview", methods=["GET"])
def preview():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10,
            allow_redirects=True,
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
            "url": response.url,
            "status_code": response.status_code,
            "title": title,
            "description": description,
            "image": image
        })

    except requests.RequestException as exc:
        return jsonify({
            "error": f"Failed to fetch URL: {str(exc)}"
        }), 500


if __name__ == "__main__":
    app.run(debug=True)