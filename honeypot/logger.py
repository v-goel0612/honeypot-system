import json
import os
from datetime import datetime, timezone

LOG_FILE = "../logs/attacks.json"

def log_attack(ip: str, port: int, attack_type: str, data: str = ""):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Load existing logs
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []

    # Check if IP already has an entry
    existing = next((e for e in logs if e["ip"] == ip), None)
    if existing:
        existing["attempts"] += 1
        existing["last_seen"] = datetime.now(timezone.utc).isoformat()
        existing["events"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "port": port,
            "type": attack_type,
            "data": data[:200]  # truncate for safety
        })
    else:
        logs.append({
            "ip": ip,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "attempts": 1,
            "events": [{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "type": attack_type,
                "data": data[:200]
            }]
        })

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

    print(f"[{attack_type}] {ip}:{port} — {data[:60]}")