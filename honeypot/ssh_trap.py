import socket
import threading
from logger import log_attack

def handle_ssh_client(conn, addr):
    ip = addr[0]
    try:
        # Send fake SSH banner
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        data = conn.recv(1024).decode(errors="replace").strip()
        log_attack(ip, 2222, "SSH_PROBE", data)

        # Send fake auth failure after a short delay
        conn.send(b"Permission denied (publickey,password).\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def start_ssh_trap(host="0.0.0.0", port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[SSH Trap] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_ssh_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_ssh_trap()