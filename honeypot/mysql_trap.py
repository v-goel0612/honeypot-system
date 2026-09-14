import socket
import threading
from logger import log_attack

MYSQL_BANNER = (
    b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x32\x00"
    b"\x08\x00\x00\x00\x6d\x7a\x40\x62\x48\x57\x26\x55\x00"
    b"\xff\xf7\xff\x02\x00\xff\x8f\x15\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x48\x7e\x39\x42\x4c\x60\x26\x4e"
    b"\x38\x61\x6a\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74"
    b"\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
)

def try_extract_username(payload: bytes) -> str:
    # MySQL handshake response: after a 32-byte fixed header, the
    # username is a null-terminated string. Best-effort parsing —
    # real clients vary, so we fall back gracefully.
    try:
        if len(payload) > 36:
            rest = payload[36:]
            end = rest.find(b"\x00")
            if end > 0:
                candidate = rest[:end]
                if candidate.isascii() and candidate.decode().isprintable():
                    return candidate.decode()
    except Exception:
        pass
    return ""

def handle_mysql_client(conn, addr):
    ip = addr[0]
    try:
        conn.send(MYSQL_BANNER)
        data = conn.recv(1024)
        if not data:
            return

        username = try_extract_username(data)
        if username:
            log_attack(ip, 3306, "MYSQL_LOGIN_ATTEMPT", f"USER:{username}")
        else:
            log_attack(ip, 3306, "MYSQL_PROBE", data.hex()[:150])

        # Always deny — we're not implementing a real SQL engine,
        # just gathering better intel on who's connecting and as who.
        conn.send(b"\xff\x15\x04\x23\x32\x38\x30\x30\x30Access denied")

        # Some clients/scanners send a second packet (e.g. a query
        # attempt) even after seeing the error — capture it if so.
        conn.settimeout(2)
        try:
            more = conn.recv(1024)
            if more:
                log_attack(ip, 3306, "MYSQL_POST_DENIAL_PACKET", more.hex()[:150])
        except socket.timeout:
            pass

    except Exception:
        pass
    finally:
        conn.close()

def start_mysql_trap(host="0.0.0.0", port=3306):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[MySQL Trap] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_mysql_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_mysql_trap()
