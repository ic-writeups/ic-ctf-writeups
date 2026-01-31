import ast, base64, zlib, re

def extract_blob(code):
    match = re.search(r"exec\(\(_\)\((b'.*?')\)\)", code, re.DOTALL)
    if not match:
        return None
    return ast.literal_eval(match.group(1))

def decode_layer(blob):
    decoded = base64.b64decode(blob[::-1])
    return zlib.decompress(decoded).decode()

with open("obs.py", "r") as f:
    code = f.read()

i = 0
while True:
    blob = extract_blob(code)
    if not blob:
        print(f"\n[{i}] Última capa alcanzada. Contenido final:\n")
        print(code)
        break
    code = decode_layer(blob)
    print(f"[{i}] Capa decodificada")
    i += 1
