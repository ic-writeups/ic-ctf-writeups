 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host auratester.ctf.pascalctf.it --port 7001
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'AuraTester2000.gyat'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'auratester.ctf.pascalctf.it'
port = int(args.PORT or 7001)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
import itertools
words = ["tungtung", "trallalero", "filippo boschi", "zaza", "lakaka", "gubbio", "cucinato"]
def encoder(phrase, steps):
    encoded_phrase = ""
    for i in range(len(phrase)):
        if phrase[i] == " ":
            encoded_phrase += phrase[i]
        elif i % steps == 0:
            encoded_phrase += str(ord(phrase[i]))
        else:
            encoded_phrase += phrase[i]
    return encoded_phrase

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
io.recvuntil(b'First of all, we need to know your name.\n')
io.sendline(b'Mateo')
io.recvuntil(b'What do you want to do little Beta?\n')
io.sendline(b'1')
for i in range(4):
    io.recvuntil(b'(yes/no)\n')
    if i % 2 == 0:
        io.sendline(b'yes')
    else:   
        io.sendline(b'no')

io.recvuntil(b'What do you want to do little Beta?\n')
io.sendline(b'3')
io.recvuntil(b'If you want to win your prize you need to decode this secret phrase: ')
secret = io.recvline().strip().decode()
decoded_phrase = ""
found = False
for k in range(3, 6): 
    if found: break
    for combo in itertools.permutations(words, k):
        phrase_candidate = " ".join(combo)
        for steps in range(2, 6): 
            if encoder(phrase_candidate, steps) == secret:
                decoded_phrase = phrase_candidate
                found = True
                log.success(f"La frase es: {decoded_phrase}")
                break
io.recvuntil(b'Type the decoded phrase to prove your worth:\n')
io.sendline(decoded_phrase.encode())
io.interactive()

