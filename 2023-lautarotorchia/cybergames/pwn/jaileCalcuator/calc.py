import socket
import os
import pty
import sys

def handle_client(conn):
    s_fd = conn.fileno()
    os.dup2(s_fd, 0)
    os.dup2(s_fd, 1)
    os.dup2(s_fd, 2)
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'\n' in data:
            break
    text = data.decode().strip()

    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text.lower():
            conn.sendall(b"Not allowed, killing\n")
            return

    # Check for forbidden characters.
    for character in ['\'', '\"']:
        if character in text.lower():
            conn.sendall(b"Not allowed, killing\n")
            return

    try:
        exec('print(' + text + ')')
    except Exception as e:
        conn.sendall(("Error: " + str(e) + "\n").encode())

def main():
    host = '0.0.0.0'
    port = 1337
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Listening on {host}:{port}")
        conn, addr = s.accept()  # Handle one connection.
        with conn:
            print(f"Connection from {addr}")
            handle_client(conn)
    sys.exit(0)

if __name__ == "__main__":
    main()

