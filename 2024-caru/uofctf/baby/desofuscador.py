import re


def xor(*args):
    res = 0
    for x in args: res ^= int(x)
    return res

def div(a, b, c, d):
    try: return (a ^ c) // (b ^ d)
    except: return 0


MOCK_CONTEXT = {
    'G0G0SQU1D': xor, 'gOg0sQuId': xor, 'g0GOsquiD': xor,
    'G0g0sQu1D_116510': xor, 'g0gosQU1d': xor, 'g0GOsquiD_37121': xor,
    'G0goSQuId_531543': div, 'G0Gosqu1D_116510': div
}

def solve():
    with open('baby.py', 'r') as f:
        content = f.read()

    def extract_list(name):
        match = re.search(rf"{name}\s*=\s*\[", content)
        if not match: return []
        
        start = match.end() - 1
        count = 0
        s = ""
        for i in range(start, len(content)):
            char = content[i]
            s += char
            if char == '[': count += 1
            elif char == ']': count -= 1
            if count == 0: break
            
        return eval(s, MOCK_CONTEXT)

    print("[*] Extrayendo listas críticas...")
    raw_data = extract_list('G0gosQu1D')  
    indices  = extract_list('SqUId')      

    print("[*] Ensamblando la flag...")
    flag = ""
    KEY = 125 

    for index in indices:
        fragment = raw_data[index]
        decoded_part = "".join(chr(x ^ KEY) for x in fragment)
        flag += decoded_part

    print(f"\n[+] FLAG: {flag}")

if __name__ == "__main__":
    solve()