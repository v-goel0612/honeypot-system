import socket
import threading
from logger import log_attack

FAKE_FILES = [
    "-rw-r--r-- 1 root root  8192 Apr 10 12:00 backup.sql",
    "-rw-r--r-- 1 root root 24576 Apr 10 12:01 users.csv",
    "-rw-r--r-- 1 root root  4096 Apr 10 12:02 config.php",
    "-rw-r--r-- 1 root root 16384 Apr 10 12:03 database.db",
]

def handle_ftp_client(conn, addr):
    ip = addr[0]
    try:
        conn.send(b"220 ProFTPD 1.3.5 Server ready.\r\n")
        while True:
            raw = conn.recv(1024)
            if not raw:
                break
            data = raw.decode(errors="replace").strip()
            if not data:
                break

            cmd = data.upper()

            if cmd.startswith("USER"):
                username = data[5:].strip()
                log_attack(ip, 2121, "FTP_LOGIN_ATTEMPT", f"USER:{username}")
                conn.send(b"331 Password required.\r\n")

            elif cmd.startswith("PASS"):
                password = data[5:].strip()
                log_attack(ip, 2121, "FTP_PASSWORD", f"PASS:{password}")
                conn.send(b"230 Login successful.\r\n")

            elif cmd.startswith("LIST") or cmd.startswith("NLST"):
                log_attack(ip, 2121, "FTP_LIST", data)
                conn.send(b"150 Here comes the directory listing.\r\n")
                for f in FAKE_FILES:
                    conn.send(f"{f}\r\n".encode())
                conn.send(b"226 Directory send OK.\r\n")

            elif cmd.startswith("PWD"):
                conn.send(b'257 "/" is the current directory.\r\n')

            elif cmd.startswith("CWD"):
                conn.send(b"250 Directory successfully changed.\r\n")

            elif cmd.startswith("TYPE"):
                conn.send(b"200 Switching to Binary mode.\r\n")

            elif cmd.startswith("RETR"):
                filename = data[5:].strip()
                log_attack(ip, 2121, "FTP_DOWNLOAD_ATTEMPT", f"FILE:{filename}")
                conn.send(b"550 Failed to open file.\r\n")

            elif cmd.startswith("STOR"):
                filename = data[5:].strip()
                log_attack(ip, 2121, "FTP_UPLOAD_ATTEMPT", f"FILE:{filename}")
                conn.send(b"550 Permission denied.\r\n")

            elif cmd == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break

            else:
                log_attack(ip, 2121, "FTP_UNKNOWN_COMMAND", data)
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
