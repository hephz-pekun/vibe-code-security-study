from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    flash,
    send_from_directory,
)
from werkzeug.utils import secure_filename
from uuid import uuid4
import os
import secrets

app = Flask(__name__)

# Secret key should come from an environment variable.
# A secure random value is generated as a fallback for development.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Simple in-memory user profile storage
user_profile = {
    "username": "john_doe",
    "profile_picture": None,
}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/", methods=["GET", "POST"])
def profile():
    if request.method == "POST":
        if "profile_picture" not in request.files:
            flash("No file selected.")
            # Fixed: avoid redirecting to request-controlled URL
            return redirect(url_for("profile"))

        file = request.files["profile_picture"]

        if file.filename == "":
            flash("No file selected.")
            # Fixed: avoid redirecting to request-controlled URL
            return redirect(url_for("profile"))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Generate unique filename
            extension = filename.rsplit(".", 1)[1].lower()
            unique_filename = f"{uuid4().hex}.{extension}"

            save_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_filename,
            )

            file.save(save_path)

            # Optional: delete old profile picture
            old_picture = user_profile.get("profile_picture")
            if old_picture:
                old_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    old_picture,
                )
                if os.path.exists(old_path):
                    os.remove(old_path)

            user_profile["profile_picture"] = unique_filename

            flash("Profile picture uploaded successfully!")
            return redirect(url_for("profile"))

        flash("Invalid file type.")
        # Fixed: avoid redirecting to request-controlled URL
        return redirect(url_for("profile"))

    return render_template_string(
        """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profile Picture Upload</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 40px;
            }
            img {
                border-radius: 50%;
                width: 200px;
                height: 200px;
                object-fit: cover;
                border: 3px solid #ccc;
            }
            .container {
                max-width: 500px;
            }
            .alert {
                color: green;
                margin-bottom: 15px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>User Profile</h1>

            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    {% for message in messages %}
                        <div class="alert">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            {% if profile_picture %}
                <img src="{{ url_for('uploaded_file', filename=profile_picture) }}"
                     alt="Profile Picture">
            {% else %}
                <p>No profile picture uploaded.</p>
            {% endif %}

            <h3>{{ username }}</h3>

            <form method="POST" enctype="multipart/form-data">
                <input type="file"
                       name="profile_picture"
                       accept=".png,.jpg,.jpeg,.gif,.webp"
                       required>
                <br><br>
                <button type="submit">Upload Picture</button>
            </form>

            <p>
                Allowed formats: PNG, JPG, JPEG, GIF, WEBP<br>
                Max size: 5 MB
            </p>
        </div>
    </body>
    </html>
    """,
        username=user_profile["username"],
        profile_picture=user_profile["profile_picture"],
    )


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
    )


@app.errorhandler(413)
def file_too_large(error):
    return (
        "<h3>File is too large. Maximum size is 5 MB.</h3>",
        413,
    )


if __name__ == "__main__":
    # Never enable Flask debug mode in production.
    # Control debugging via environment variables if needed.
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )