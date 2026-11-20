import os
from functools import wraps
from pathlib import Path
from flask import Flask, abort, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Base directory where user reports are stored (e.g., ./reports/<user_id>/<filename>)
REPORTS_ROOT = Path(os.environ.get("REPORTS_DIR", "./reports")).resolve()

# Allowed file extensions for download
ALLOWED_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".txt", ".json"}


def get_current_user_id() -> str:
    """
    Simulated authentication helper.
    In production, replace this with your actual session/JWT user lookup
    (e.g., flask_login.current_user.id or decoded JWT 'sub' claim).
    """
    user_id = request.headers.get("X-User-ID")
    if not user_id:
        abort(401, description="Authentication required.")
    # Sanitize user_id so it cannot contain path traversal characters
    return secure_filename(user_id)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        request.user_id = get_current_user_id()
        return f(*args, **kwargs)

    return decorated


def is_allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


@app.route("/api/reports", methods=["GET"])
@require_auth
def list_user_reports():
    """Lists available reports for the authenticated user."""
    user_dir = (REPORTS_ROOT / request.user_id).resolve()

    # Ensure the resolved directory is strictly inside REPORTS_ROOT
    if not user_dir.is_relative_to(REPORTS_ROOT) or not user_dir.is_dir():
        return jsonify({"reports": []}), 200

    reports = [
        f.name
        for f in user_dir.iterdir()
        if f.is_file() and is_allowed_file(f.name)
    ]
    return jsonify({"reports": sorted(reports)}), 200


@app.route("/api/reports/<path:filename>", methods=["GET"])
@require_auth
def download_user_report(filename: str):
    """
    Securely downloads a specific report belonging to the authenticated user.
    Protects against path traversal and unauthorized cross-user access.
    """
    # 1. Strip any directory components from the requested filename
    safe_name = secure_filename(filename)
    if not safe_name or not is_allowed_file(safe_name):
        abort(400, description="Invalid or unsupported file name.")

    # 2. Scope the lookup strictly to the authenticated user's directory
    user_dir = (REPORTS_ROOT / request.user_id).resolve()
    if not user_dir.is_relative_to(REPORTS_ROOT):
        abort(403, description="Access denied.")

    target_file = (user_dir / safe_name).resolve()

    # 3. Verify the target file exists and hasn't escaped user_dir (e.g., via symlinks)
    if not target_file.is_relative_to(user_dir) or not target_file.is_file():
        abort(404, description="Report not found.")

    # 4. Serve the file as an attachment (triggers browser download)
    return send_from_directory(
        directory=user_dir,
        path=safe_name,
        as_attachment=True,
        download_name=safe_name,
        max_age=0,  # Prevent caching of sensitive user reports
    )


# --- Error Handlers ---
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_http_error(error):
    return jsonify({"error": error.name, "message": error.description}), error.code


# --- Local Testing Setup ---
def _seed_sample_data():
    """Creates sample report files for quick local testing."""
    sample_dir = REPORTS_ROOT / "user_123"
    sample_dir.mkdir(parents=True, exist_ok=True)
    sample_file = sample_dir / "monthly_summary.csv"
    if not sample_file.exists():
        sample_file.write_text("date,revenue,expenses\n2026-11-01,5000,1200\n", encoding="utf-8")


if __name__ == "__main__":
    _seed_sample_data()
    # Test locally with:
    # curl -H "X-User-ID: user_123" http://127.0.0.1:5000/api/reports
    # curl -O -J -H "X-User-ID: user_123" http://127.0.0.1:5000/api/reports/monthly_summary.csv
    app.run(host="127.0.0.1", port=5000, debug=False)