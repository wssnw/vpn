import socket
import threading
import tkinter as tk

server_socket = None
is_running = False

def handle_client(client_socket):
    try:
        request = client_socket.recv(1024)
        print(f"Empfangen: {request}")
        client_socket.send(b"VPN Tunnel Aktiv (Mega Basic)\n")
    except:
        pass
    finally:
        client_socket.close()

def run_server():
    global server_socket, is_running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(5)
    is_running = True
    status_label.config(text="Status: Läuft auf Port 8080", fg="green")
    
    while is_running:
        try:
            server_socket.settimeout(1.0)
            client, addr = server_socket.accept()
            print(f"Verbindung von {addr}")
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break

def start_vpn():
    threading.Thread(target=run_server, daemon=True).start()

def stop_vpn():
    global server_socket, is_running
    is_running = False
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
    status_label.config(text="Status: Gestoppt", fg="red")
    print("VPN gestoppt.")

# GUI erstellen
root = tk.Tk()
root.title("Mega Basic VPN")
root.geometry("300x200")

title_label = tk.Label(root, text="VPN Steuerung", font=("Arial", 14))
title_label.pack(pady=10)

status_label = tk.Label(root, text="Status: Gestoppt", font=("Arial", 10), fg="red")
status_label.pack(pady=5)

start_btn = tk.Button(root, text="Start VPN", bg="green", fg="white", font=("Arial", 10), width=15, command=start_vpn)
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="Stop VPN", bg="red", fg="white", font=("Arial", 10), width=15, command=stop_vpn)
stop_btn.pack(pady=5)

root.mainloop()
