#!/usr/bin/env python3
# solve_almost_classic.py

def atbash(s: str) -> str:
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            # 'a' + ('z' - c)
            result.append(chr(ord('a') + (ord('z') - ord(c))))
        elif 'A' <= c <= 'Z':
            result.append(chr(ord('A') + (ord('Z') - ord(c))))
        else:
            result.append(c)
    return ''.join(result)

def main():
    with open("communication.txt", "r") as f:
        for line in f:
            line = line.rstrip()
            # Separamos la etiqueta (X:/Y:) del texto cifrado
            if not line: 
                continue
            tag, cipher = line.split(":", 1)
            plain = atbash(cipher.strip())
            print(f"{tag}: {plain}")

if __name__ == "__main__":
    main()
