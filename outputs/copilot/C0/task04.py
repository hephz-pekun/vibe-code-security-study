from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# In-memory storage
notes = {}
next_id = 1


# Helper function
def get_note_or_404(note_id):
    note = notes.get(note_id)
    if not note:
        return None
    return note


# Create a note
@app.route("/notes", methods=["POST"])
def create_note():
    global next_id

    data = request.get_json()

    if not data or "title" not in data or "content" not in data:
        return jsonify({
            "error": "Both 'title' and 'content' are required"
        }), 400

    note = {
        "id": next_id,
        "title": data["title"],
        "content": data["content"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

    notes[next_id] = note
    next_id += 1

    return jsonify(note), 201


# Get all notes
@app.route("/notes", methods=["GET"])
def get_notes():
    return jsonify(list(notes.values())), 200


# Get a single note
@app.route("/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    note = get_note_or_404(note_id)

    if not note:
        return jsonify({"error": "Note not found"}), 404

    return jsonify(note), 200


# Update a note
@app.route("/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    note = get_note_or_404(note_id)

    if not note:
        return jsonify({"error": "Note not found"}), 404

    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    if "title" in data:
        note["title"] = data["title"]

    if "content" in data:
        note["content"] = data["content"]

    note["updated_at"] = datetime.utcnow().isoformat()

    return jsonify(note), 200


# Delete a note
@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    note = get_note_or_404(note_id)

    if not note:
        return jsonify({"error": "Note not found"}), 404

    del notes[note_id]

    return jsonify({
        "message": f"Note {note_id} deleted successfully"
    }), 200


# Health check
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Notes API is running"
    })


if __name__ == "__main__":
    app.run(debug=True)