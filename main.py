import socket
import threading

def handle_client(client_socket):
    request = client_socket.recv(1024)
    print(f"Empfangen: {request}")
    client_socket.send(b"VPN Tunnel Aktiv (Mega Basic)\n")
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 8080))
    server.listen(5)
    print("Mega Basic VPN-Tunnel läuft auf Port 8080...")
    
    while True:
        client, addr = server.accept()
        print(f"Verbindung von {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    main()
