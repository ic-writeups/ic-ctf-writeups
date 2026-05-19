from pwn import *

p = remote("10.43.35.10", 1337)

print(p.recvuntil(b":"))
p.sendline(b"SuperSecretAIPassword")
print(repr(p.recvall()))