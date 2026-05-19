from Crypto.Util.number import inverse

# datos
z1 = 0x3f12c87a7847acffea7cbbda8e65cfbbcaa987124424861b754773f48f9099cf
z2 = 0x45e656fff1a82884c860a495cb39c1e8634992e4e10c21887d64250c39e3c9bd

r  = 0xf1f9868668a5add66dd96d6712eab1fe6a94da480e2863a1671864b927b29494
s1 = 0xf6b890ba847741d34aace32aec779d81c41006d6b710e203deedb8442ff613f2
s2 = 0x8d30c4a40494387ed709bdd069c059e6303f8e0087646b69ea5d4933598f5a8d

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 1. recover nonce k
k = ((z1 - z2) * inverse(s1 - s2, n)) % n

# 2. recover private key d
d = ((s1 * k - z1) * inverse(r, n)) % n

print("k:", hex(k))
print("private key d:", hex(d))