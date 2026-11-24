
from flask import Flask, jsonify

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


# ===== START SERVER =====

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
