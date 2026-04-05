with open('stackstrings_med', 'rb') as f:
    data = f.read()

# los datos cifrados están en el archivo en offset 0x20d0
enc = bytearray(data[0x20d0 : 0x20d0 + 0xbd])

# funcion auxiliar
def rol32(val, n):
    val &= 0xFFFFFFFF
    n   &= 31
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

# extraer parametros del binario
# estos bytes están cifrados con XOR simples hardcodeados en el asm:
# r12  = buf[0xb8] ^ 0x36  →  longitud esperada del input
# r15d = combinación de buf[0xb9..0xbc] con claves fijas
expected_len = enc[0xb8] ^ 0x36

b1 = enc[0xb9] ^ 0x19   # byte bajo  del hash esperado
b2 = enc[0xba] ^ 0x95
b3 = enc[0xbb] ^ 0xc7
b4 = enc[0xbc] ^ 0x0a   # byte alto

r15d = (b4 << 24) | (b3 << 16) | (b2 << 8) | b1   # = 0xc8597e93

# estado inicial del generador (hardcodeado en el asm)
eax  = 0xa97288ed
ebx  = 0x9e3779b9   # constante de Knuth / Fibonacci hashing
r9d  = 0

# Loop: calcular cada carácter de la contraseña
flag = []

for i in range(expected_len):

    # rama izquierda: genera "sil" (target cifrado)
    esi = (ebx ^ 0xc19ef49e) & 0xFFFFFFFF
    esi = rol32(esi, i & 7)
    ecx = esi ^ (esi >> 16)
    ecx = ecx ^ (ecx >> 8)
    sil = (ecx ^ enc[0x95 + i]) & 0xFF   # enc[0x95+i] es el stream cifrado

    # rama derecha: genera "dl" (máscara del input)
    edx = (eax ^ r15d) & 0xFFFFFFFF
    edx = rol32(edx, r9d & 7)
    ecx2 = edx ^ (edx >> 15)
    ecx2 = ecx2 ^ (ecx2 >> 7)
    dl   = ecx2 & 0xFF

    # invertir: input[i] = sil XOR dl
    flag.append(sil ^ dl)

    # -actualizar estado para la próxima iteración
    eax  = (eax + 0x85ebca6b) & 0xFFFFFFFF
    ebx  = (ebx + 0x9e3779b9) & 0xFFFFFFFF
    r9d  = (r9d + 3)           & 0xFFFFFFFF

print(bytes(flag).decode())
