#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES

# 1. Claves en Base64 → bytes
k1 = base64.b64decode("h+NvKyaJFRhpn7lRWo0JGGcSk7TOd2ltibSSI1CGDCk=")
k2 = base64.b64decode("CznIYU0rBgmzSb7WyqYfj+WKyDSXbbnsa8Wp/IRvUOc=")
k3 = base64.b64decode("ihpLsXPURUTwH4ULO9/87rHRCQibQO6+V4/QKJL7Bgg=")

# 2. Leemos intercept.txt y extraemos blobs X/Y
blobs = []
with open("intercept.txt","r") as f:
    for line in f:
        line = line.strip()
        if line.startswith(("X:","Y:")):
            b64 = line.split(":",1)[1].strip()
            blobs.append(base64.b64decode(b64))

# 3. Función de desencriptación EDE-ECB
def decrypt_3aes_ede_ecb(blob, k1,k2,k3):
    # D₃
    s1 = AES.new(k3, AES.MODE_ECB).decrypt(blob)
    # E₂
    s2 = AES.new(k2, AES.MODE_ECB).encrypt(s1)
    # D₁
    pt = AES.new(k1, AES.MODE_ECB).decrypt(s2)
    # Quitar PKCS#7 (si existe)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad):
        return pt[:-pad]
    return pt

# 4. Desencriptamos y mostramos
for idx, blob in enumerate(blobs, 1):
    pt = decrypt_3aes_ede_ecb(blob, k1,k2,k3)
    print(f"=== BLOQUE #{idx} ({len(blob)} bytes) ===")
    print(pt.decode('utf-8', errors='ignore'))
    print()
