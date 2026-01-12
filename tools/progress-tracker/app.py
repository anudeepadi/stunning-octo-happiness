#!/usr/bin/env python3
"""
CyberLab Progress Tracker API
Flask backend for tracking lab progress (optional - UI uses localStorage)
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Data storage (simple file-based for simplicity)
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
PROGRESS_FILE = DATA_DIR / "progress.json"


def load_progress():
    """Load progress from file."""
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, "r") as f:
            return json.load(f)
    return {
        "completed_labs": [],
        "completed_tasks": {},
        "flags_captured": 0,
        "started_at": None,
    }


def save_progress(data):
    """Save progress to file."""
    with open(PROGRESS_FILE, "w") as f:
        json.dump(data, f, indent=2)


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route("/api/progress", methods=["GET"])
def get_progress():
    """Get current progress."""
    return jsonify(load_progress())


@app.route("/api/progress", methods=["POST"])
def update_progress():
    """Update progress."""
    data = request.json
    progress = load_progress()

    if "lab_id" in data:
        lab_id = data["lab_id"]
        if lab_id not in progress["completed_labs"]:
            progress["completed_labs"].append(lab_id)

    if "task" in data:
        lab_id = data.get("lab_id", "unknown")
        task_id = data["task"]
        if lab_id not in progress["completed_tasks"]:
            progress["completed_tasks"][lab_id] = []
        if task_id not in progress["completed_tasks"][lab_id]:
            progress["completed_tasks"][lab_id].append(task_id)

    if "flag" in data:
        progress["flags_captured"] += 1

    if not progress["started_at"]:
        progress["started_at"] = datetime.now().isoformat()

    save_progress(progress)
    return jsonify({"status": "updated", "progress": progress})


@app.route("/api/progress/reset", methods=["POST"])
def reset_progress():
    """Reset all progress."""
    progress = {
        "completed_labs": [],
        "completed_tasks": {},
        "flags_captured": 0,
        "started_at": None,
    }
    save_progress(progress)
    return jsonify({"status": "reset", "progress": progress})


@app.route("/api/progress/export", methods=["GET"])
def export_progress():
    """Export progress as JSON."""
    progress = load_progress()
    progress["exported_at"] = datetime.now().isoformat()
    return jsonify(progress)


@app.route("/api/progress/import", methods=["POST"])
def import_progress():
    """Import progress from JSON."""
    data = request.json
    if data:
        save_progress(data)
        return jsonify({"status": "imported"})
    return jsonify({"error": "No data provided"}), 400


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get overall statistics."""
    progress = load_progress()
    return jsonify({
        "total_labs": 50,
        "completed_labs": len(progress["completed_labs"]),
        "total_tasks": 200,
        "completed_tasks": sum(len(t) for t in progress["completed_tasks"].values()),
        "flags_captured": progress["flags_captured"],
        "started_at": progress["started_at"],
        "completion_percentage": round(len(progress["completed_labs"]) / 50 * 100, 1),
    })


if __name__ == "__main__":
    print("CyberLab Progress Tracker API")
    print("Running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
