import socket
import threading
from logger import log_attack

FAKE_FS = {
    "/": ["etc", "home", "var", "usr", "tmp"],
    "/etc": ["passwd", "shadow", "hostname", "hosts"],
    "/home": ["admin", "ubuntu"],
    "/home/ubuntu": ["documents", "downloads", ".bash_history"],
    "/var": ["log", "www"],
    "/tmp": []
}

FAKE_FILES = {
    "/etc/hostname": "ubuntu-server\n",
    "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n",
}

def handle_command(cmd, ip, cwd="/home/ubuntu"):
    cmd = cmd.strip()
    if not cmd:
        return ""

    parts = cmd.split()
    command = parts[0]

    if command == "ls":
        path = parts[1] if len(parts) > 1 else cwd
        files = FAKE_FS.get(path, ["No such file or directory"])
        return "  ".join(files) + "\r\n"
    elif command == "pwd":
        return cwd + "\r\n"
    elif command == "whoami":
        return "root\r\n"
    elif command == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\r\n"
    elif command == "uname":
        return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
    elif command == "cat":
        if len(parts) > 1:
            return FAKE_FILES.get(parts[1], f"cat: {parts[1]}: No such file or directory\r\n")
        return ""
    elif command == "cd":
        return ""
    elif command == "echo":
        return " ".join(parts[1:]) + "\r\n"
    elif command == "wget" or command == "curl":
        log_attack(ip, 2323, "DOWNLOAD_ATTEMPT", cmd)
        return "Connecting... Connection refused\r\n"
    elif command == "exit" or command == "logout":
        return "EXIT"
    else:
        log_attack(ip, 2323, "COMMAND_ATTEMPT", cmd)
        return f"-bash: {command}: command not found\r\n"

def handle_telnet_client(conn, addr):
    ip = addr[0]
    try:
        conn.send(b"\r\nUbuntu 22.04 LTS\r\nlogin: ")
        username = conn.recv(1024).decode(errors="replace").strip()
        conn.send(b"Password: ")
        password = conn.recv(1024).decode(errors="replace").strip()
        log_attack(ip, 2323, "TELNET_LOGIN_ATTEMPT", f"USER:{username} PASS:{password}")

        conn.send(b"\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        log_attack(ip, 2323, "TELNET_SHELL_ACCESS", f"Shell opened by {ip}")
        conn.send(b"root@ubuntu-server:~# ")

        cmd_buffer = ""
        cwd = "/home/ubuntu"

        while True:
            data = conn.recv(1024)
            if not data:
                break
            for char in data.decode(errors="replace"):
                if char in ("\r", "\n"):
                    conn.send(b"\r\n")
                    if cmd_buffer.strip():
                        log_attack(ip, 2323, "COMMAND_ATTEMPT", cmd_buffer.strip())
                        result = handle_command(cmd_buffer, ip, cwd)
                        if result == "EXIT":
                            conn.send(b"logout\r\n")
                            conn.close()
                            return
                        conn.send(result.encode())
                    cmd_buffer = ""
                    conn.send(b"root@ubuntu-server:~# ")
                elif char == "\x7f":
                    if cmd_buffer:
                        cmd_buffer = cmd_buffer[:-1]
                        conn.send(b"\b \b")
                else:
                    cmd_buffer += char
                    conn.send(char.encode())
    except Exception:
        pass
    finally:
        conn.close()

def start_telnet_trap(host="0.0.0.0", port=2323):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[Telnet Trap] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_telnet_trap()
