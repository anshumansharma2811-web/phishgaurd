
from flask import Flask, jsonify, request
from urllib.parse import urlsplit

app = Flask(__name__)


# ===== ROOT ENDPOINT =====

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "PhishGuard",
        "message": "PhishGuard Backend API",
        "version": "1.0.0"
    })


# ===== HEALTH CHECK ENDPOINT =====

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "online",
        "service": "PhishGuard API",
        "model_loaded": False,
        "mode": "development"
    }), 200


# ===== URL PREDICTION ENDPOINT =====

@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON request."
        }), 400

    url = data.get("url")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "success": False,
            "error": "URL is required."
        }), 400

    url = url.strip()

    if len(url) > 4096:
        return jsonify({
            "success": False,
            "error": "URL is too long."
        }), 400

    try:
        parsed_url = urlsplit(url)

        if (
            parsed_url.scheme not in ("http", "https")
            or not parsed_url.hostname
            or any(char.isspace() for char in url)
        ):
            raise ValueError("Invalid URL")

        # Validate the port if one is provided.
        _ = parsed_url.port

    except ValueError:
        return jsonify({
            "success": False,
            "error": "Please enter a valid HTTP or HTTPS URL."
        }), 400

    return jsonify({
        "success": True,
        "url": url,
        "hostname": parsed_url.hostname,
        "protocol": parsed_url.scheme,
        "prediction": None,
        "model_loaded": False,
        "mode": "preview",
        "message": "URL validated. ML prediction is not yet available."
    }), 200

# ===== START SERVER =====

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
