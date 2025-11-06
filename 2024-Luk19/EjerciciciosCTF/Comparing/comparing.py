def parse_even(s):
    """
    even(val1, val3, i):
      s = A + i + reverse(A)
      donde A = str(val1) + str(val3)
    Probamos i de 1 o 2 dígitos (0..15) y deducimos |A| = (len(s)-len(i))//2
    """
    for len_i in (1, 2):
        if (len(s) - len_i) % 2 != 0:
            continue
        A_len = (len(s) - len_i) // 2
        if A_len <= 0:
            continue
        A = s[:A_len]
        idx_str = s[A_len:A_len + len_i]
        mirror = s[A_len + len_i:]
        if mirror != A[::-1]:
            continue
        try:
            idx = int(idx_str)
        except ValueError:
            continue
        if not (0 <= idx <= 15):
            continue
        # A = str(val1)+str(val3) → probamos todas las divisiones
        for split in range(1, len(A)):
            val1 = int(A[:split])
            val3 = int(A[split:])
            if 32 <= val1 <= 126 and 32 <= val3 <= 126:
                return val1, val3, idx
    return None


def parse_odd(s):
    """
    odd(val1, val3, i):
      s = A + i
      donde A = str(val1) + str(val3)
    Probamos i de 1 o 2 dígitos (0..15).
    """
    for len_i in (1, 2):
        if len(s) <= len_i:
            continue
        idx_str = s[-len_i:]
        try:
            idx = int(idx_str)
        except ValueError:
            continue
        if not (0 <= idx <= 15):
            continue
        A = s[:-len_i]
        for split in range(1, len(A)):
            val1 = int(A[:split])
            val3 = int(A[split:])
            if 32 <= val1 <= 126 and 32 <= val3 <= 126:
                return val1, val3, idx
    return None


def parse_line(s):
    r = parse_even(s)
    if r:
        return r
    r = parse_odd(s)
    if r:
        return r
    raise ValueError("No se pudo parsear: " + s)


def main():
    with open("output.txt") as f:
        lines = [line.strip() for line in f if line.strip()]

    n_pairs = len(lines)                 # líneas = #pares
    flag_len = n_pairs * 2               # flag tiene 2 * #pares
    flag = ['?'] * flag_len

    # Procesar de a pares de líneas (crítico)
    for k in range(0, len(lines), 2):
        a0, b0, i1 = parse_line(lines[k])       # primer char de cada par (i1 e i2)
        a1, b1, i2 = parse_line(lines[k + 1])   # segundo char de cada par (i1 e i2)

        # Asignaciones correctas:
        flag[2 * i1]     = chr(a0)
        flag[2 * i1 + 1] = chr(a1)
        flag[2 * i2]     = chr(b0)
        flag[2 * i2 + 1] = chr(b1)

    print("Flag:", "".join(flag))


if __name__ == "__main__":
    main()

