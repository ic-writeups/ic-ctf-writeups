from Crypto.Cipher import AES

# Clave AES-128 de 16 bytes todos ceros
key = bytes.fromhex('00000000000000000000000000000000')

# Leer el archivo cifrado
with open('ecb.dat', 'rb') as f:
    ciphertext = f.read()

# Configurar cifrador en modo ECB
cipher = AES.new(key, AES.MODE_ECB)

# Desencriptar y quitar padding PKCS#7
plaintext = cipher.decrypt(ciphertext)
pad_len = plaintext[-1]
if all(b == pad_len for b in plaintext[-pad_len:]):
    plaintext = plaintext[:-pad_len]

# Mostrar el resultado
print(plaintext.decode('utf-8'))
