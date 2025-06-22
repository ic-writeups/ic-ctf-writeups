from Crypto.Cipher import AES
from Crypto.Util import Counter

def main():
    # Parámetros dados (hex)
    key_hex = "11111111111111111111111111111111"
    iv_hex = "99999999999999999999999999999999"

    # Convertir key e iv a bytes
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    # Crear contador para AES CTR (128 bits, valor inicial = iv)
    iv_int = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv_int)

    # Inicializar cifrador AES en modo CTR
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Leer archivo cifrado
    with open('ctr.dat', 'rb') as f:
        encrypted_data = f.read()

    # Descifrar
    plaintext = cipher.decrypt(encrypted_data)

    # Decodificar y mostrar flag
    print(plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()
