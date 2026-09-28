flag = 'brunner{' + input() + '}'
n = int.from_bytes(flag.encode())
lis = [n//(i+2) - n//(i+3) for i in range(9**5)]
assert sum(lis) == 22263691028918788395010325066307464924652601045336492930678310479674861811846
