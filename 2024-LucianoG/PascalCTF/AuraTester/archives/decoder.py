def decode(encoded, steps):
    out = []
    i = 0 
    j = 0 

    while j < len(encoded):
        if encoded[j] == " ":
            out.append(" ")
            i += 1
            j += 1
            continue

        if i % steps == 0:
            num = ""
            while j < len(encoded) and encoded[j].isdigit():
                num += encoded[j]
                j += 1
            out.append(chr(int(num)))
            i += 1
        else:
            out.append(encoded[j])
            i += 1
            j += 1

    return "".join(out)

encoded = input("Ingresa la frase codificada: ").strip()

for s in range(2, 6):
    try:
        print(s, decode(encoded, s))
    except:
        pass