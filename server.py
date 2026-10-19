"""
VPN Server (PC A)

Layers (see diagram):
    UI                -> tkinter window (VPNServerApp)
    TUN Interface     -> TunInterface   (virtual network card, Linux, needs root)
    Encryption Engine -> EncryptionEngine (Fernet / AES, key from shared passphrase)
    Python            -> sockets + threads
    Scapy             -> parses raw IP packets for the log

Install:  pip install scapy cryptography
Run:      sudo python3 vpn_server.py     (root is needed to create the TUN device)

If the TUN device can't be created (Windows, no root), the server falls back
to the old demo mode: it receives encrypted "packets", logs them and answers
"Bestaetigt".
"""

import base64
import os
import socket
import struct
import subprocess
import threading
import tkinter as tk

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import fcntl  # Linux / macOS only
except ImportError:
    fcntl = None

try:
    from scapy.all import IP
except ImportError:
    IP = None

PORT = 8080
SHARED_SECRET = "change-this-secret"   # must be identical on the client
TUN_NAME = "vpn0"
TUN_IP = "10.8.0.1/24"


# ---------------------------------------------------------------- Encryption
class EncryptionEngine:
    def __init__(self, passphrase):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"vpn-demo-salt",
            iterations=200_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        self.fernet = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self.fernet.decrypt(token)


# ------------------------------------------------------------------ TUN
class TunInterface:
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name=TUN_NAME, address=TUN_IP):
        if fcntl is None or not os.path.exists("/dev/net/tun"):
            raise RuntimeError("TUN wird nur unter Linux unterstuetzt")
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode(), self.IFF_TUN | self.IFF_NO_PI)
        fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        subprocess.run(["ip", "addr", "add", address, "dev", name], check=False)
        subprocess.run(["ip", "link", "set", name, "up"], check=True)
        self.name = name

    def read(self, size=2048) -> bytes:
        return os.read(self.fd, size)

    def write(self, packet: bytes):
        os.write(self.fd, packet)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


# --------------------------------------------------------------------- UI
class VPNServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN Server (PC A)")
        self.root.geometry("380x280")
        self.root.configure(bg="#f8f9fa")

        self.status_label = tk.Label(
            root,
            text="Status: Server Gestoppt",
            bg="#f8d7da",
            fg="#721c24",
            font=("Arial", 13, "bold"),
            relief="solid",
            bd=1
        )
        self.status_label.pack(fill="x", padx=20, pady=20, ipady=8)

        btn_frame = tk.Frame(root, bg="#f8f9fa")
        btn_frame.pack(fill="x", padx=20, pady=5)

        self.start_btn = tk.Button(
            btn_frame,
            text="Server Starten",
            bg="#d1e7dd",
            fg="#0f5132",
            font=("Arial", 10, "bold"),
            command=self.start_server
        )
        self.start_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.stop_btn = tk.Button(
            btn_frame,
            text="Server Stoppen",
            bg="#f8d7da",
            fg="#721c24",
            font=("Arial", 10, "bold"),
            state=tk.DISABLED,
            command=self.stop_server
        )
        self.stop_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))

        self.log_box = tk.Text(root, height=5, width=42, font=("Consolas", 9))
        self.log_box.pack(padx=20, pady=10)

        self.is_running = False
        self.server_socket = None
        self.tun = None
        self.engine = EncryptionEngine(SHARED_SECRET)
        self.send_lock = threading.Lock()

    def log(self, message):
        try:
            self.root.after(0, self._log_ui, message)
        except Exception:
            print(message)

    def _log_ui(self, message):
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)

    # ------------------------------------------------------ start / stop
    def start_server(self):
        if not self.is_running:
            self.is_running = True
            self.status_label.config(text=f"Status: Server Aktiv (Port {PORT})", bg="#d1e7dd", fg="#0f5132")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            threading.Thread(target=self.run_server_loop, daemon=True).start()

    def stop_server(self):
        if self.is_running:
            self.is_running = False
            try:
                if self.server_socket:
                    self.server_socket.close()
            except Exception:
                pass
            if self.tun:
                self.tun.close()
                self.tun = None
            self.status_label.config(text="Status: Server Gestoppt", bg="#f8d7da", fg="#721c24")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.log("Server wurde gestoppt.")

    # ------------------------------------------------ framing + crypto
    @staticmethod
    def recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_encrypted(self, conn, data: bytes):
        token = self.engine.encrypt(data)
        with self.send_lock:
            conn.sendall(struct.pack("!I", len(token)) + token)

    def recv_encrypted(self, conn):
        header = self.recv_exact(conn, 4)
        if header is None:
            return None
        (length,) = struct.unpack("!I", header)
        token = self.recv_exact(conn, length)
        if token is None:
            return None
        return self.engine.decrypt(token)

    # ------------------------------------------------------ scapy
    def describe_packet(self, raw: bytes) -> str:
        if IP is None:
            return f"{len(raw)} Bytes"
        try:
            return IP(raw).summary()
        except Exception:
            return f"{len(raw)} Bytes"

    # ------------------------------------------------------ TUN -> client
    def tun_to_client(self, conn):
        import select
        while self.is_running and self.tun:
            try:
                ready, _, _ = select.select([self.tun.fd], [], [], 1.0)
                if not ready:
                    continue
                packet = self.tun.read()
                self.send_encrypted(conn, packet)
                self.log(f"TUN -> Client: {self.describe_packet(packet)}")
            except Exception:
                break

    # ------------------------------------------------------ main loop
    def run_server_loop(self):
        try:
            try:
                self.tun = TunInterface()
                self.log(f"TUN {self.tun.name} aktiv ({TUN_IP})")
            except Exception as e:
                self.tun = None
                self.log(f"Kein TUN ({e}). Demo-Modus.")

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", PORT))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            self.log("Warte auf Client-Verbindungen...")

            while self.is_running:
                try:
                    conn, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                self.log(f"Verbunden mit: {addr[0]}")
                conn.settimeout(1.0)
                try:
                    self.send_encrypted(conn, "Willkommen vom VPN-Server!".encode("utf-8"))

                    if self.tun:
                        threading.Thread(target=self.tun_to_client, args=(conn,), daemon=True).start()

                    while self.is_running:
                        try:
                            data = self.recv_encrypted(conn)
                        except socket.timeout:
                            continue
                        if data is None:
                            break

                        if self.tun:
                            self.log(f"Client -> TUN: {self.describe_packet(data)}")
                            self.tun.write(data)
                        else:
                            self.log(f"Paket empfangen: {self.describe_packet(data)}")
                            self.send_encrypted(conn, "Bestaetigt".encode("utf-8"))
                except Exception as e:
                    self.log(f"Client-Fehler: {e}")
                finally:
                    conn.close()
                    self.log("Client getrennt. Warte auf neuen Client...")
        except Exception as e:
            self.log(f"Start-Fehler: {e}")
            self.root.after(0, self.stop_server)


if __name__ == "__main__":
    root = tk.Tk()
    app = VPNServerApp(root)
    root.mainloop()
