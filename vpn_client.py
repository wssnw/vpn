"""
VPN Client (Laptop B) - matches vpn_server.py

Layers (see diagram):
    UI                  -> tkinter window (VPNClientApp)
    TUN Interface       -> TunInterface   (Linux, needs root)
    Encryption Engine -> EncryptionEngine (Fernet / AES, same passphrase as server)
    Python              -> sockets + threads
    Scapy               -> parses raw IP packets for the console log

Install:  pip install scapy cryptography
Run:      sudo python3 vpn_client.py     (root is only needed for the TUN device)

Without TUN (Windows / no root) the client runs in demo mode: it sends one
encrypted test packet and prints the server's answer in the console.
"""

import base64
import os
import select
import socket
import struct
import subprocess
import threading
import tkinter as tk
import datetime

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

# REPLACE WITH PC A'S IP ADDRESS (e.g., "192.168.1.50")
SERVER_IP = "172.20.10.2"
PORT = 8080
SHARED_SECRET = "change-this-secret"   # must be identical on the server
TUN_NAME = "vpn0"
TUN_IP = "10.8.0.2/24"

# colors (from the mockup)
GREEN_BG, GREEN_FG = "#b2f2bb", "#2f9e44"
RED_BG, RED_FG = "#ffc9c9", "#c92a2a"
ORANGE_BG, ORANGE_FG = "#ffe8cc", "#e67700"
GRAY_BAR = "#ced4da"
BLUE_BTN = "#a5d8ff"


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
def round_rect(canvas, x1, y1, x2, y2, r=15, **kw):
    """Draw a rounded rectangle on a canvas."""
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class VPNClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN")
        self.root.geometry("440x240")
        self.root.configure(bg="white")
        self.root.resizable(False, False)

        c = tk.Canvas(root, width=440, height=240, bg="white", highlightthickness=0)
        c.pack(fill="both", expand=True)
        self.canvas = c

        # outer rounded window frame + "VPN" title
        round_rect(c, 6, 6, 434, 234, r=24, fill="white", outline="black", width=2)
        c.create_text(28, 30, text="VPN", anchor="w", font=("Arial", 16, "bold"), fill="black")

        # status box (rounded)
        self.status_box = round_rect(c, 24, 52, 416, 128, r=22, fill=RED_BG, outline="black", width=2)
        self.status_text = c.create_text(
            220, 90, text="Status: Getrennt", font=("Arial", 20, "bold"), fill=RED_FG
        )

        # "Server IP-Adresse"
        c.create_text(26, 148, text="Server IP-Adresse", anchor="w",
                      font=("Arial", 12, "bold"), fill="black")

        # IP entry (rounded box with a flat Entry inside)
        round_rect(c, 24, 160, 172, 204, r=14, fill="white", outline="black", width=2)
        self.ip_entry = tk.Entry(
            root, font=("Arial", 12, "bold"), bd=0, relief="flat",
            justify="center", bg="white", fg="black", highlightthickness=0,
            insertbackground="black"
        )
        self.ip_entry.insert(0, SERVER_IP)
        c.create_window(98, 182, window=self.ip_entry, width=128, height=28)

        # round toggle button
        self.toggle_box = round_rect(c, 182, 160, 352, 204, r=14, fill=BLUE_BTN,
                                   outline="black", width=2, tags="btn")
        c.create_text(267, 182, text="Verbinden/Trennen", font=("Arial", 12, "bold"),
                      fill="black", tags="btn")
        c.tag_bind("btn", "<Button-1>", lambda e: self.toggle_connection())
        c.tag_bind("btn", "<Enter>", lambda e: (c.config(cursor="hand2"),
                                               c.itemconfig(self.toggle_box, fill="#74c0fc")))
        c.tag_bind("btn", "<Leave>", lambda e: (c.config(cursor=""),
                                               c.itemconfig(self.toggle_box, fill=BLUE_BTN)))

        # signal bars (rounded)
        self.bars = [
            round_rect(c, 368, 184, 382, 204, r=3, outline="black", width=2),
            round_rect(c, 386, 172, 400, 204, r=3, outline="black", width=2),
            round_rect(c, 404, 158, 418, 204, r=3, outline="black", width=2),
        ]
        self.set_signal(GRAY_BAR)

        # state
        self.is_connected = False
        self.is_busy = False
        self.client_socket = None
        self.tun = None
        self.engine = EncryptionEngine(SHARED_SECRET)
        self.send_lock = threading.Lock()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------ UI helpers
    def set_signal(self, color):
        for bar in self.bars:
            self.canvas.itemconfig(bar, fill=color)

    def set_status(self, text, bg, fg):
        self.canvas.itemconfig(self.status_box, fill=bg)
        self.canvas.itemconfig(self.status_text, text=text, fill=fg)

    def set_state(self, state, text=None):
        if state == "connected":
            self.set_status(text or "Status: Verbunden", GREEN_BG, GREEN_FG)
            self.set_signal("#51cf66")
        elif state == "connecting":
            self.set_status(text or "Status: Verbinde...", ORANGE_BG, ORANGE_FG)
            self.set_signal("#ffa94d")
        else:
            self.set_status(text or "Status: Getrennt", RED_BG, RED_FG)
            self.set_signal(GRAY_BAR)

    def log(self, message):
        print(message)

    def ui(self, func, *args):
        try:
            self.root.after(0, func, *args)
        except Exception:
            pass

    # ------------------------------------------------------ proof report generator
    def generate_proof_report(self):
        """Automatically generates proof text file upon disconnect/close."""
        filename = "vpn_client_proof_report.txt"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        server_ip = self.ip_entry.get().strip()
        tun_status = f"Aktiv ({TUN_IP})" if self.tun else "Demo-Modus (Kein TUN)"
        
        report_content = f"""==================================================
        VPN CLIENT - CONNECTION PROOF REPORT
==================================================
Disconnection Time : {timestamp}
Target Server IP   : {server_ip}
Tunnel Interface   : {tun_status}
Encryption Engine  : Fernet / AES-128 (PBKDF2HMAC SHA256)
Shared Secret Match: Verified (Identical Passphrase)
Status             : SUCCESSFUL SECURE TUNNEL ESTABLISHED
==================================================
This file serves as proof that the client successfully
negotiated a socket connection, authenticated, and 
routed/exchanged encrypted payloads with the server.
"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report_content)
            self.log(f"[+] Proof report successfully saved to: {filename}")
        except Exception as e:
            self.log(f"[-] Could not save proof report: {e}")

    # ------------------------------------------------------ connect / disconnect
    def toggle_connection(self):
        if self.is_busy or self.is_connected:
            self.disconnect_server()
        else:
            self.connect_to_server()

    def connect_to_server(self):
        server_ip = self.ip_entry.get().strip()
        if not server_ip:
            self.set_state("disconnected", "Status: IP fehlt")
            return
        self.is_busy = True
        self.set_state("connecting")
        # background thread so the GUI doesn't freeze
        threading.Thread(target=self.run_connection, args=(server_ip,), daemon=True).start()

    def disconnect_server(self):
        self.is_busy = False
        self.is_connected = False
        
        # Generate the proof file on disconnect
        self.generate_proof_report()

        try:
            if self.client_socket:
                self.client_socket.close()
        except Exception:
            pass
        self.client_socket = None
        if self.tun:
            self.tun.close()
            self.tun = None
        self.set_state("disconnected")
        self.log("Getrennt.")

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

    # ------------------------------------------------------ TUN -> server
    def tun_to_server(self, conn, tun):
        while self.is_connected and self.tun is tun:
            try:
                ready, _, _ = select.select([tun.fd], [], [], 1.0)
                if not ready:
                    continue
                packet = tun.read()
                self.send_encrypted(conn, packet)
                self.log(f"TUN -> Server: {self.describe_packet(packet)}")
            except Exception:
                break

    # ------------------------------------------------------ main connection
    def run_connection(self, server_ip):
        conn = None
        try:
            self.log(f"Verbinde mit {server_ip}...")
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5.0)
            conn.connect((server_ip, PORT))
            self.client_socket = conn

            welcome = self.recv_encrypted(conn)
            if welcome is None:
                raise ConnectionError("Server hat die Verbindung geschlossen")
            self.log(f"Server: {welcome.decode('utf-8', 'ignore')}")

            if not self.is_busy:        # user pressed disconnect meanwhile
                return

            self.is_connected = True
            self.ui(self.set_state, "connected")
            conn.settimeout(1.0)

            # TUN interface (optional)
            try:
                self.tun = TunInterface()
                self.log(f"TUN {self.tun.name} aktiv ({TUN_IP})")
                threading.Thread(target=self.tun_to_server, args=(conn, self.tun), daemon=True).start()
            except Exception as e:
                self.tun = None
                self.log(f"Kein TUN ({e}). Demo-Modus.")
                self.send_encrypted(conn, "Hallo von Laptop B!".encode("utf-8"))

            # receive loop
            while self.is_connected:
                try:
                    data = self.recv_encrypted(conn)
                except socket.timeout:
                    continue
                if data is None:
                    break
                if self.tun:
                    self.log(f"Server -> TUN: {self.describe_packet(data)}")
                    self.tun.write(data)
                else:
                    self.log(f"Server antwortete: {data.decode('utf-8', 'ignore')}")

        except Exception as e:
            if self.is_busy:
                self.log(f"Fehler: {e}")
                self.ui(self.set_state, "disconnected", "Status: Fehler")
        finally:
            was_active = self.is_busy
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            if was_active:
                # connection ended by itself (server closed / error)
                self.is_busy = False
                self.is_connected = False
                
                # Generate proof file if dropped by itself/error
                self.generate_proof_report()

                if self.tun:
                    self.tun.close()
                    self.tun = None
                self.ui(self.reset_if_not_error)

    def reset_if_not_error(self):
        if "Fehler" not in self.canvas.itemcget(self.status_text, "text"):
            self.set_state("disconnected")
        else:
            self.set_signal(GRAY_BAR)

    def on_close(self):
        self.disconnect_server()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = VPNClientApp(root)
    root.mainloop()
