import threading
from ssh_trap import start_ssh_trap
from ftp_trap import start_ftp_trap
from telnet_trap import start_telnet_trap
from mysql_trap import start_mysql_trap
from redis_trap import start_redis_trap

if __name__ == "__main__":
    print("=== Honeypot System Starting ===")
    threads = [
        threading.Thread(target=start_ssh_trap, daemon=True),
        threading.Thread(target=start_ftp_trap, daemon=True),
        threading.Thread(target=start_telnet_trap, daemon=True),
        threading.Thread(target=start_mysql_trap, daemon=True),
        threading.Thread(target=start_redis_trap, daemon=True),
    ]
    for t in threads:
        t.start()
    print("All traps active. Press Ctrl+C to stop.")
    for t in threads:
        t.join()
