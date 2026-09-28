#!/usr/bin/env python3
# Hidden but definitely not - boroCTF (Reversing)
#
# El binario "password_protected" (ELF64 stripped) pide un password.
# Por analisis estatico con objdump descubri dos cosas:
#
#  A) El password esperado NO esta como string suelto: se arma en el
#     stack con instrucciones movabs (immediates de 8 bytes en
#     little-endian) justo antes del strcmp.
#
#  B) Si el password es correcto, el binario recorre un buffer oculto
#     y le hace XOR 0x7 a cada byte antes de imprimirlo: ese es el flag
#     real, escondido para que "strings" no lo muestre.
#
# Este script reconstruye ambas cosas sin tener que ejecutar el binario.

# ---------- A) Reconstruccion del password ----------
# Immediates encontrados (en orden de escritura sobre el stack):
#   0x6174533565746152 -> "Rate5Sta"
#   0x00007372          -> "rs"
#   ... luego, a partir de strlen("Rate5Stars")=10, se anexan:
#   0x4765737561636542 -> "BecauseG"
#   0x6c61684374616572 -> "reatChal"
#   0x0065676e656c6c61  -> "allenge"
def le_qword_to_str(val):
    return val.to_bytes(8, "little").rstrip(b"\x00").decode()

password = (
    le_qword_to_str(0x6174533565746152) +   # "Rate5Sta"
    "rs" +                                   # mov edx, 0x7372
    le_qword_to_str(0x4765737561636542) +    # "BecauseG"
    le_qword_to_str(0x6c61684374616572)[:6] +# "reatCh" (se solapa el resto)
    le_qword_to_str(0x0065676e656c6c61)      # "allenge"
)
# Resultado directo y simple:
password = "Rate5StarsBecauseGreatChallenge"
print("[+] Password esperado por el strcmp:")
print("    " + password)

# ---------- B) Flag oculto (XOR 0x7) ----------
# Bytes escritos de a uno en [rbp-0x1a0] ... (mov byte ptr, ...)
enc = [
    0x65,0x68,0x75,0x68,0x44,0x53,0x41,0x7c,0x4e,0x58,0x4f,0x3f,
    0x58,0x4a,0x47,0x30,0x6e,0x69,0x60,0x58,0x54,0x73,0x55,0x36,
    0x69,0x60,0x32,0x58,0x64,0x4f,0x66,0x6b,0x74,0x7a,
]
flag = "".join(chr(b ^ 0x7) for b in enc)
print("[+] Flag oculto (cada byte XOR 0x7):")
print("    " + flag)
