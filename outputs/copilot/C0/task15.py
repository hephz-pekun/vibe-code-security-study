from flask import Flask, send_from_directory, abort, jsonify
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Directory where report files are stored
REPORTS_DIR = Path("reports").resolve()

# Create directory if it doesn't exist
REPORTS_DIR.mkdir(exist_ok=True)


@app.route("/reports", methods=["GET"])
def list_reports():
    """
    List available report files.
    """
    files = [
        f.name
        for f in REPORTS_DIR.iterdir()
        if f.is_file()
    ]
    return jsonify({"reports": files})


@app.route("/reports/download/<path:filename>", methods=["GET"])
def download_report(filename):
    """
    Download a report file by name.

    Example:
    GET /reports/download/report_2026.pdf
    """
    # Sanitize filename to prevent path traversal attacks
    safe_filename = secure_filename(filename)

    if not safe_filename:
        abort(400, description="Invalid filename")

    file_path = REPORTS_DIR / safe_filename

    if not file_path.exists() or not file_path.is_file():
        abort(404, description="Report not found")

    return send_from_directory(
        directory=REPORTS_DIR,
        path=safe_filename,
        as_attachment=True
    )


@app.errorhandler(400)
def handle_bad_request(error):
    return jsonify({"error": str(error)}), 400


@app.errorhandler(404)
def handle_not_found(error):
    return jsonify({"error": str(error)}), 404


if __name__ == "__main__":
    # Example test file
    sample = REPORTS_DIR / "sample_report.txt"
    if not sample.exists():
        sample.write_text("Example report content.")

    app.run(host="0.0.0.0", port=5000, debug=True)