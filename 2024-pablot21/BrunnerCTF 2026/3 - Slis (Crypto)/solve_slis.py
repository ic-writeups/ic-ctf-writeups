#!/usr/bin/env python3
# Solver para "Slis" (BrunnerCTF - Crypto)
#
# El reto define:
#   flag = 'brunner{' + input() + '}'
#   n = int.from_bytes(flag.encode())            # entero big-endian de los bytes de la flag
#   lis = [n//(i+2) - n//(i+3) for i in range(9**5)]
#   assert sum(lis) == S
#
# La suma es TELESCOPICA: sum_{i=0}^{M-1} (n//(i+2) - n//(i+3)) = n//2 - n//(M+2)
# con M = 9**5. Entonces g(n) = n//2 - n//(M+2) == S.
# g es no decreciente, asi que hago binary search del menor n con g(n) >= S y
# recorro el rango que da exactamente S buscando el n cuyos bytes son una flag valida.

S = 22263691028918788395010325066307464924652601045336492930678310479674861811846
M = 9**5
K = M + 2   # 59051

def g(n):
    return n//2 - n//K

# menor n con g(n) >= S
lo, hi = 0, 4*S
while lo < hi:
    mid = (lo + hi)//2
    if g(mid) >= S:
        hi = mid
    else:
        lo = mid + 1

for cand in range(lo, lo + 70000):
    if g(cand) != S:
        break
    b = cand.to_bytes((cand.bit_length() + 7)//8, 'big')
    if b.startswith(b'brunner{') and b.endswith(b'}'):
        try:
            s = b.decode()
        except UnicodeDecodeError:
            continue
        if s.isprintable():
            print(s)
            break
