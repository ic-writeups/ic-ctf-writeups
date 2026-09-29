#!/usr/bin/env python3
# Et Tu, Brute - boroCTF (Cripto)
# "Et tu, Brute?" -> Julio Cesar -> cifrado Cesar.
# A Cesar lo apunalaron, y el reto pide "revertir el dano".
# El texto cifrado se descifra con un corrimiento de 3 (ROT-3 inverso).
CIFRADO = "erurFWI{@iu13qgq0pru3}"

def cesar(texto, shift):
    out = []
    for c in texto:
        if c.isupper():
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        elif c.islower():
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        else:
            out.append(c)  # numeros y simbolos no se tocan
    return "".join(out)

# Probamos todos los corrimientos para evidenciar el analisis
print("== Fuerza bruta de todos los corrimientos ==")
for s in range(26):
    print(f"shift {s:2d}: {cesar(CIFRADO, s)}")

print("\n== Flag (shift 3) ==")
print(cesar(CIFRADO, 3))
