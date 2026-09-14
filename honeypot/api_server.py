import json
import os
from flask import Flask, jsonify, request

app = Flask(__name__)
LOG_FILE = "/home/ubuntu/honeypot-system/logs/attacks.json"
API_KEY = os.getenv("HONEYPOT_API_KEY", "supersecret-key")

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

@app.route("/api/attacks", methods=["GET"])
@require_api_key
def get_attacks():
    return jsonify(load_logs())

@app.route("/api/stats", methods=["GET"])
@require_api_key
def get_stats():
    logs = load_logs()
    total_attempts = sum(e["attempts"] for e in logs)
    top_ips = sorted(logs, key=lambda x: x["attempts"], reverse=True)[:5]
    attack_types = {}
    for entry in logs:
        for ev in entry.get("events", []):
            t = ev["type"]
            attack_types[t] = attack_types.get(t, 0) + 1
    return jsonify({
        "total_unique_ips": len(logs),
        "total_attempts": total_attempts,
        "top_ips": [{"ip": e["ip"], "attempts": e["attempts"]} for e in top_ips],
        "attack_types": attack_types
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)