#!/usr/bin/env python3
from math import gcd

def main():
    # Parámetros del reto
    n = 102064367305175623005003367803963735992210717721719563218760598878897771063019
    e = 65537
    c = 66538583650087752653364112099322882026083260207958188191147900019851853145222

    # Factores obtenidos de Factordb https://factordb.com/index.php?query=102064367305175623005003367803963735992210717721719563218760598878897771063019
    p = 305875545128432734240552595430305723491
    q = 333679396508538352589365351078683227609

    # Verificar
    if p * q != n:
        print("Error: p*q != n")
        return
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        print("Error: gcd(e, phi) != 1")
        return

    d = pow(e, -1, phi)
    # Descifrar
    m = pow(c, d, n)
    # Convertir a bytes
    k = (m.bit_length() + 7) // 8
    plaintext_bytes = m.to_bytes(k, 'big')
    try:
        plaintext = plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        plaintext = plaintext_bytes.decode('latin-1', errors='ignore')
    print("Flag:", plaintext)

if __name__ == "__main__":
    main()
