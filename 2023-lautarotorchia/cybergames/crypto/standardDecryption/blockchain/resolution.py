from Crypto.Cipher import AES

# Parámetros proporcionados
key = bytes.fromhex('00000000000000000000000000000000')
iv  = bytes.fromhex('01020304050607080102030405060708')

# Leer el archivo cifrado
with open('cbc.dat', 'rb') as f:
    ciphertext = f.read()

# Crear el objeto AES en modo CBC
cipher = AES.new(key, AES.MODE_CBC, iv)

# Desencriptar y eliminar padding PKCS#7
plaintext = cipher.decrypt(ciphertext)
pad_len = plaintext[-1]
if all(b == pad_len for b in plaintext[-pad_len:]):
    plaintext = plaintext[:-pad_len]

# Mostrar la flag
print(plaintext.decode('utf-8'))
