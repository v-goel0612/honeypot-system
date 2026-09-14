import socket
import threading
import paramiko
import logging
from logger import log_attack

logging.getLogger("paramiko").setLevel(logging.WARNING)

import os
KEY_PATH = "/home/ubuntu/honeypot-system/honeypot/ssh_host_key"
if os.path.exists(KEY_PATH):
    HOST_KEY = paramiko.RSAKey(filename=KEY_PATH)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_PATH)

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

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip
        self.username = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        log_attack(self.ip, 2222, "SSH_LOGIN_ATTEMPT", f"USER:{username} PASS:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"

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
            content = FAKE_FILES.get(parts[1], f"cat: {parts[1]}: No such file or directory\r\n")
            return content
        return ""

    elif command == "cd":
        return ""

    elif command == "echo":
        return " ".join(parts[1:]) + "\r\n"

    elif command == "ifconfig" or command == "ip":
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n        inet 10.0.0.4 netmask 255.255.255.0\r\n"

    elif command == "ps":
        return "  PID TTY          TIME CMD\r\n    1 ?        00:00:02 systemd\r\n  412 ?        00:00:00 sshd\r\n  891 pts/0    00:00:00 bash\r\n"

    elif command == "wget" or command == "curl":
        log_attack(ip, 2222, "DOWNLOAD_ATTEMPT", cmd)
        return f"Connecting... Connection refused\r\n"

    elif command == "exit" or command == "logout":
        return "EXIT"

    else:
        log_attack(ip, 2222, "COMMAND_ATTEMPT", cmd)
        return f"-bash: {command}: command not found\r\n"

def handle_ssh_client(conn, addr):
    ip = addr[0]
    transport = None
    try:
        transport = paramiko.Transport(conn)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(ip)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            return

        log_attack(ip, 2222, "SSH_SHELL_ACCESS", f"Shell opened by {ip}")

        chan.send(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        chan.send(f"Last login: Mon Apr 12 18:23:11 2026 from 192.168.1.1\r\n")
        chan.send(f"root@ubuntu-server:~# ")

        cmd_buffer = ""
        cwd = "/home/ubuntu"

        while True:
            data = chan.recv(1024)
            if not data:
                break

            for char in data.decode("utf-8", errors="replace"):
                if char in ("\r", "\n"):
                    chan.send("\r\n")
                    if cmd_buffer.strip():
                        log_attack(ip, 2222, "COMMAND_ATTEMPT", cmd_buffer.strip())
                        result = handle_command(cmd_buffer, ip, cwd)
                        if result == "EXIT":
                            chan.send("logout\r\n")
                            chan.close()
                            return
                        chan.send(result)
                    cmd_buffer = ""
                    chan.send("root@ubuntu-server:~# ")
                elif char == "\x7f":
                    if cmd_buffer:
                        cmd_buffer = cmd_buffer[:-1]
                        chan.send("\b \b")
                else:
                    cmd_buffer += char
                    chan.send(char)

    except Exception:
        pass
    finally:
        if transport:
            transport.close()
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
