def rot13_extended(s):
    """
    Realiza una sustitución ROT13 extendida a letras, dígitos y símbolos básicos.
    """
    abc = 'abcdefghijklmnopqrstuvwxyz'
    ABC = abc.upper()
    rot13 = abc[13:] + abc[:13]
    ROT13 = ABC[13:] + ABC[:13]

    # Mapear letras ROT13 + dígitos rot5 + símbolos
    trans = str.maketrans(
        abc + ABC + '0123456789_-',
        rot13 + ROT13 + '5678901234-_'
    )
    return s.translate(trans)

def invert_characters(s, symbol_map=None):
    """
    Invierte el alfabeto (a<->z), números (0<->9), y símbolos opcionales.
    """
    if symbol_map is None:
        symbol_map = {}

    result = []
    for c in s:
        if c.islower():
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif c.isupper():
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif c.isdigit():
            result.append(str(9 - int(c)))
        elif c in symbol_map:
            result.append(symbol_map[c])
        else:
            result.append(c)
    return ''.join(result)

def deobfuscate(string):
    """
    Aplica las 3 capas de desofuscación secuencialmente.
    """
    step1 = rot13_extended(string)
    step2 = invert_characters(step1, {'_': '=', '=': '_', '-': '+', '+': '-'})
    step3 = invert_characters(step2, {'_': '*', '*': '_', '-': '!', '!': '-'})
    return step3

if __name__ == "__main__":
    command2 = "./yby.fu #FX!PREG{5osh0p9265a*9aq*0y88c}"

    flag = deobfuscate(command2)
    print("Flag desofuscada:")
    print(flag)
