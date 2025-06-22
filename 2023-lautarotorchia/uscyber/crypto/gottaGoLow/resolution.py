#!/usr/bin/env python3
import sys
import re

def integer_cube_root(n):
    lo = 0
    hi = 1 << ((n.bit_length() + 2) // 3 + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        cube = mid * mid * mid
        if cube < n:
            lo = mid + 1
        else:
            hi = mid
    # Ajuste final para exactitud
    if lo * lo * lo == n:
        return lo
    if (lo - 1) * (lo - 1) * (lo - 1) == n:
        return lo - 1
    return lo - 1

def parse_output_file(path):
    # Lee output.txt y extrae el valor de ciphertext
    ciphertext = None
    with open(path, 'r') as f:
        for line in f:
            m = re.match(r'\s*ciphertext\s*=\s*(\d+)', line)
            if m:
                ciphertext = int(m.group(1))
                break
    if ciphertext is None:
        print(f"No se encontró 'ciphertext' en {path}", file=sys.stderr)
        sys.exit(1)
    return ciphertext

def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <ruta_output.txt>", file=sys.stderr)
        sys.exit(1)
    output_path = sys.argv[1]
    ciphertext = parse_output_file(output_path)
    root = integer_cube_root(ciphertext)
    if root * root * root != ciphertext:
        print("Error: no se obtuvo raíz cúbica exacta. Verifique e y tamaño del mensaje.", file=sys.stderr)
        sys.exit(1)
    byte_len = (root.bit_length() + 7) // 8
    plaintext_bytes = root.to_bytes(byte_len, byteorder='big')
    try:
        plaintext = plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        plaintext = plaintext_bytes.decode('latin-1', errors='ignore')
    print("Flag recuperada:")
    print(plaintext)

if __name__ == "__main__":
    main()
