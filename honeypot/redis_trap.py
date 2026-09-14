import socket
import threading
from logger import log_attack

FAKE_INFO = (
    "# Server\r\nredis_version:7.2.4\r\nos:Linux 5.15.0-91-generic x86_64\r\n"
    "process_id:1042\r\ntcp_port:6379\r\nuptime_in_seconds:284913\r\n"
    "# Memory\r\nused_memory_human:12.44M\r\n"
    "# Keyspace\r\ndb0:keys=47,expires=3,avg_ttl=0\r\n"
)

FAKE_KEYS = ["session:8841", "user:1002:profile", "cache:homepage",
             "config:app_settings", "queue:emails"]

def parse_resp_command(buf: bytes):
    try:
        text = buf.decode(errors="replace")
        if not text.startswith("*"):
            return None
        lines = text.split("\r\n")
        n = int(lines[0][1:])
        args = []
        idx = 1
        for _ in range(n):
            idx += 1
            args.append(lines[idx])
            idx += 1
        return args
    except Exception:
        return None

def handle_command(args, ip):
    if not args:
        return b"-ERR unknown command\r\n"
    cmd = args[0].upper()

    if cmd == "AUTH":
        pw = args[1] if len(args) > 1 else ""
        log_attack(ip, 6379, "REDIS_AUTH_ATTEMPT", f"PASS:{pw}")
        return b"+OK\r\n"

    elif cmd == "PING":
        return b"+PONG\r\n"

    elif cmd == "INFO":
        log_attack(ip, 6379, "REDIS_RECON", "INFO")
        body = FAKE_INFO
        return f"${len(body)}\r\n{body}\r\n".encode()

    elif cmd == "DBSIZE":
        log_attack(ip, 6379, "REDIS_RECON", "DBSIZE")
        return b":47\r\n"

    elif cmd == "KEYS":
        log_attack(ip, 6379, "REDIS_RECON", f"KEYS {args[1] if len(args)>1 else ''}")
        resp = f"*{len(FAKE_KEYS)}\r\n"
        for k in FAKE_KEYS:
            resp += f"${len(k)}\r\n{k}\r\n"
        return resp.encode()

    elif cmd == "CONFIG":
        log_attack(ip, 6379, "REDIS_RECON", " ".join(args))
        return b"*0\r\n"

    elif cmd == "GET":
        key = args[1] if len(args) > 1 else ""
        log_attack(ip, 6379, "REDIS_GET_ATTEMPT", f"KEY:{key}")
        return b"$-1\r\n"

    elif cmd == "QUIT":
        return b"+OK\r\n"

    else:
        log_attack(ip, 6379, "REDIS_UNKNOWN_COMMAND", " ".join(args)[:200])
        return b"-ERR unknown command\r\n"

def handle_redis_client(conn, addr):
    ip = addr[0]
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            args = parse_resp_command(data)
            if args:
                response = handle_command(args, ip)
            else:
                raw = data.decode(errors="replace").strip()
                log_attack(ip, 6379, "REDIS_PROBE", raw[:200])
                response = b"-ERR unknown command\r\n"

            conn.send(response)
    except Exception:
        pass
    finally:
        conn.close()

def start_redis_trap(host="0.0.0.0", port=6379):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[Redis Trap] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_redis_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_redis_trap()
