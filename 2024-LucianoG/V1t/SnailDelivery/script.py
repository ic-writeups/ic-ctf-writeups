xor_key = bytes([0x12, 0x45, 0x78, 0xab, 0xcd, 0xef])
expected = bytes.fromhex(
    "65740cd1be81272c"
    "14f5a9dc7f740e99"
    "bf964c36149abab0"
    "27232799fbdb2175"
    "754f9cff8e713800"
)


# Reconstruir la flag
flag = bytearray()
for i, b in enumerate(expected):
    flag.append(b ^ xor_key[i % 6])

print("Flag reconstruida:")
print(flag.decode(errors="replace"))
