import urllib.parse

# Cadena codificada
encoded = b'%0eb%cf%8c%f8%b9%c0:%ec%e0y%e3%d3r%de"%01P\t%bb%d5!%cf%a7#W9(%adg%a5N%d3%afF%90=%17x)A>%d1%d0%99%08o-%b9M'
decoded_bytes = urllib.parse.unquote_to_bytes(encoded.decode())

# Lista de enteros que se usan para XOR
key = [
    69, 83, 248, 247, 201, 230, 244, 121, 219, 149,
    77, 175, 159, 11, 129, 102, 49, 30, 62, 228,
    158, 79, 255, 208, 124, 102, 127, 119, 154, 15,
    145, 121, 140, 229, 51, 221, 77, 72, 73, 28,
    30, 78, 225, 229, 172, 57, 45, 65, 252, 48
]

# XOR entre cada par
flag_bytes = bytes([x ^ y for x, y in zip(key, decoded_bytes)])

#print de la flag
print("Flag:", flag_bytes.decode())
