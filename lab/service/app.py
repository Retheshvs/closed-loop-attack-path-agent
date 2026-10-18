import json
import os
from flask import Flask, jsonify

app = Flask(__name__)

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config.json")


def load_config():
    """Loads the service configuration from the mounted JSON file."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    # Fallback to local default if running outside container
    return {
        "name": os.environ.get("SERVICE_NAME", "unknown"),
        "zone": os.environ.get("SERVICE_ZONE", "internal"),
        "version": "1.0.0",
        "vulns": [],
        "creds_weak": False,
        "ports": [5000],
        "holds": None,
    }


@app.route("/info", methods=["GET"])
def get_info():
    """Returns the simulated service posture, network zone, and vulnerabilities."""
    config = load_config()
    return jsonify(config)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    config = load_config()
    return jsonify({
        "status": "healthy",
        "service": config.get("name", "unknown"),
        "version": config.get("version", "1.0.0"),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
