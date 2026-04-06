import random

data = "cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0"

encripted_flag = bytes.fromhex(data)

random.seed(1337)

decrypted_flag = ""

for byte in encripted_flag:
    random_key = random.randint(0, 255)
    decrypted_char = chr(byte ^ random_key)
    decrypted_flag += decrypted_char

print(f"La flag: {decrypted_flag}")