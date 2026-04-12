import threading
from ssh_trap import start_ssh_trap
from ftp_trap import start_ftp_trap

if __name__ == "__main__":
    print("=== Honeypot System Starting ===")
    threads = [
        threading.Thread(target=start_ssh_trap, daemon=True),
        threading.Thread(target=start_ftp_trap, daemon=True),
    ]
    for t in threads:
        t.start()
    print("All traps active. Press Ctrl+C to stop.")
    for t in threads:
        t.join()