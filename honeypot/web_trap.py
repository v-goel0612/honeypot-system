from flask import Flask, request, jsonify
from logger import log_attack

app = Flask(__name__)

FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body>
  <h2>System Administrator Login</h2>
  <form method="POST" action="/admin/login">
    <input name="username" placeholder="Username"/><br>
    <input name="password" type="password" placeholder="Password"/><br>
    <button type="submit">Login</button>
  </form>
</body></html>"""

@app.route("/admin/login", methods=["GET"])
def login_page():
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    log_attack(ip, 8080, "WEB_PAGE_VISIT", f"UA:{ua[:100]}")
    return FAKE_LOGIN_HTML

@app.route("/admin/login", methods=["POST"])
def login_attempt():
    ip = request.remote_addr
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ua = request.headers.get("User-Agent", "")
    log_attack(ip, 8080, "WEB_LOGIN_ATTEMPT", f"user={username}&pass={password}&ua={ua[:50]}")
    # Always return auth failure
    return FAKE_LOGIN_HTML.replace("</body>", "<p style='color:red'>Invalid credentials.</p></body>")

@app.route("/", methods=["GET"])
def index():
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    log_attack(ip, 8080, "WEB_PAGE_VISIT", f"PATH:/ UA:{ua[:100]}")
    return FAKE_LOGIN_HTML

@app.route("/<path:path>", methods=["GET", "POST"])
def catch_scans(path):
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    log_attack(ip, 8080, "WEB_SCAN", f"PATH:/{path} UA:{ua[:100]}")
    return "404 Not Found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
