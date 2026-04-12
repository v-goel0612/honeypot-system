import socket
import threading
from logger import log_attack

def handle_ftp_client(conn, addr):
    ip = addr[0]
    try:
        conn.send(b"220 ProFTPD 1.3.5 Server ready.\r\n")
        while True:
            data = conn.recv(1024).decode(errors="replace").strip()
            if not data:
                break
            if data.upper().startswith("USER"):
                username = data[5:].strip()
                log_attack(ip, 2121, "FTP_LOGIN_ATTEMPT", f"USER:{username}")
                conn.send(b"331 Password required.\r\n")
            elif data.upper().startswith("PASS"):
                password = data[5:].strip()
                log_attack(ip, 2121, "FTP_PASSWORD", f"PASS:{password}")
                conn.send(b"530 Login incorrect.\r\n")
                break
            elif data.upper() == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break
            else:
                conn.send(b"500 Unknown command.\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def start_ftp_trap(host="0.0.0.0", port=2121):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[FTP Trap] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_ftp_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_ftp_trap()