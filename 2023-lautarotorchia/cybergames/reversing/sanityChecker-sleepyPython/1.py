import time
import os

def deobfuscate1(string):
    mapping = {
        'a': 'n', 'b': 'o', 'c': 'p', 'd': 'q', 'e': 'r', 'f': 's', 'g': 't',
        'h': 'u', 'i': 'v', 'j': 'w', 'k': 'x', 'l': 'y', 'm': 'z',
        'n': 'a', 'o': 'b', 'p': 'c', 'q': 'd', 'r': 'e', 's': 'f', 't': 'g',
        'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm',

        'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T',
        'H': 'U', 'I': 'V', 'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z',
        'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G',
        'U': 'H', 'V': 'I', 'W': 'J', 'X': 'K', 'Y': 'L', 'Z': 'M',

        '0': '5', '1': '6', '2': '7', '3': '8', '4': '9',
        '5': '0', '6': '1', '7': '2', '8': '3', '9': '4',

        '_': '-', '-': '_'
    }
    return ''.join(mapping.get(c, c) for c in string)


def deobfuscate2(string):
    def reverse_alpha(c):
        if 'a' <= c <= 'z':
            return chr(ord('z') - (ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            return chr(ord('Z') - (ord(c) - ord('A')))
        return c
    digit_map = {str(i): str(9 - i) for i in range(10)}
    symbol_map = {'_': '=', '=': '_', '-': '+', '+': '-'}
    result = []
    for c in string:
        if c.isalpha():
            result.append(reverse_alpha(c))
        elif c in digit_map:
            result.append(digit_map[c])
        elif c in symbol_map:
            result.append(symbol_map[c])
        else:
            result.append(c)
    return ''.join(result)


def deobfuscate3(string):
    def reverse_char(c):
        if 'a' <= c <= 'z':
            return chr(ord('z') - (ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            return chr(ord('Z') - (ord(c) - ord('A')))
        elif '0' <= c <= '9':
            return str(9 - int(c))
        elif c == '_':
            return '*'
        elif c == '*':
            return '_'
        elif c == '-':
            return '!'
        elif c == '!':
            return '-'
        else:
            return c

    return ''.join(reverse_char(c) for c in string)

command1 = "puzbq _k yby.fu"
command2 = "./yby.fu #FX!PREG{5osh0p9265a*9aq*0y88c}"


data = """
#+/ova/onfu
# FX!PREG{6*j6yy*y89i8*l5h*05z82u6a1*u8e8}

rpub !a 's5IZEtVONDNNNNNNNNNNNNZNCtNONNNNNORNNNNNNNONNNNNNNNNNVN8NNNNNNNNNNNNNRNNBNNB
NRNNVNNsNNLNNNNRNNNNDNNNNNNNNNONNNNNNNNNNRNNNNNNNNNNRNZNNNNNNNNDNjNNNNNNNNtN
NNNNNNNNNjNNNNDNNNPxNjNNNNNNNXDQNNNNNNNNcNZNNNNNNNNpNNNNNNNNNOjNNNNNNNNNNDNN
NNNNNNNONNNNONNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNWtUNNNNNNNNzNpNNNNNNNNNRNNN
NNNNNNRNNNNSNNNNNONNNNNNNNNNRNNNNNNNNNNDNNNNNNNNjDZNNNNNNNQONjNNNNNNNNNDNNNN
NNNNNDNNNNDNNNNNVNNNNNNNNNNtNNNNNNNNNPNNNNNNNNQpNDNNNNNNNAjONNNNNNNNNONNNNNN
NNNONNNNOtNNNWNgNNNNNNNNxQ5NNNNNNNPDCDNNNNNNNVNPNNNNNNNNvNVNNNNNNNNNRNNNNNNN
NNVNNNNTNNNNbP5NNNNNNNPtCDNNNNNNNXN4NNNNNNNN3NRNNNNNNNQjNDNNNNNNNNtNNNNNNNNN
ONNNNNDNNNODNjNNNNNNNSNQNNNNNNNNHNZNNNNNNNNjNNNNNNNNNQNNNNNNNNNNPNNNNNNNNNNR
NNNNONNNNVNQNNNNNNNNtNZNNNNNNNPNNjNNNNNNNPDNNNNNNNNNWNNNNNNNNNNRNNNNNNNNNNDN
NNNRNNNNGPRNNNNNNNOZVDNNNNNNNRjuNNNNNNNNxNNNNNNNNNPDNNNNNNNNNNDNNNNNNNNNH_I5
MNDNNNODNjNNNNNNNSNQNNNNNNNNHNZNNNNNNNNjNNNNNNNNNQNNNNNNNNNNPNNNNNNNNNOD0KEx
ONNNNTjtNNNNNNNNoPNNNNNNNNOfVNNNNNNNNQDNNNNNNNNNANNNNNNNNNNRNNNNNNNNNSUyqTDT
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNONNNNNNNNNNHhI5MNDN
NNPDYDNNNNNNNWN4NNNNNNNNxQ5NNNNNNNOjNtNNNNNNNUNPNNNNNNNNNDNNNNNNNNNRNNNNVNNN
NNHNNNOUGyHNNtNNjNDNNNNQNNNNNNNNNNXNNZNRNNNNNDNNNNNNNNNRNNNNSNNNNNZNNNOUGyHN
x7bQPSYuoyi242Q6DN2PB_yI1dfioTyvAwDioTDgoTyhqKtgrQt7YGL5YaAiYwVNNtNNNNfNNNNO
NNNNOtNNNNNNtDNNNNNNPjNNNNNNNNQEMp0gNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNO5N
NNNFNNNNNNNNNNNNNNNNNNNNNNNNNWNNNNNtNNNNNNNNNNNNNNNNNNNNNNNNNNpNNNNFNNNNNNNN
NNNNNNNNNNNNNNNNNNjNNNNFNNNNNNNNNNNNNNNNNNNNNNNNNQ9NNNNFNNNNNNNNNNNNNNNNNNNN
NNNNNSDNNNNFNNNNNNNNNNNNNNNNNNNNNNNNNXjNNNNtNNNNNNNNNNNNNNNNNNNNNNNNNRHNNNNF
NNNNNNNNNNNNNNNNNNNNNNNNNYfNNNNtNNNNNNNNNNNNNNNNNNNNNNNNNNRNNNNFNNNNNNNNNNNN
NNNNNNNNNNNNNP3NNNNvNNNNNNNNNNNNNNNNNNNNNNNNNNOmoTIypNOjqKEmNS4sp8EuL7gsL7ue
K7MunJjNK64fnJWwK8A5LKW5K76unJ9NK64wrTSsMzyhLJkcrzHNpUWcoaEzNS4snKAiLmx0K8Aw
LJ0zNUA5pzAgpNOfnJWwYaAiYwLNE5kWDxAsZv98NRqZFHWQKmVhANOUGRyPD63lYwVhADOUGRyP
D63lYwZ5NS4WIR6sMTIlMJqcp8EypyEAD7kiozIHLJWfMDOsK7qgo70sp8EupaEsKjOsFIEAK8Wy
M7ymqTIlIR6QoT4hMIEuLzkyNNNNNNVNNDNQNNDNNjNQNNRNODNONNZNNjNNNNRNONOoNNNNRNNN
NNNNNNNKnJxANNNSNTHNNNNDNNNNSTycQDNNONOiNNNNRNNNNUHnnDxNNNZNrDNNNONNNNP5xMLT
NNNPNVHNNNNNNNNNxQ5NNNNNNNNVNNNNNNNNNBNENNNNNNNNzQ5NNNNNNNNVNNNNNNNNNXNENNNN
NNNNPRNNNNNNNNNVNNNNNNNNNNuNNNNNNNNN7Q3NNNNNNNNTNNNNNDNNNNNNNNNNNNNN9Q3NNNNN
NNNTNNNNNtNNNNNNNNNNNNNN1Q3NNNNNNNNTNNNNOjNNNNNNNNNNNNNN3Q3NNNNNNNNTNNNNPDNN
NNNNNNNNNNNN_Q3NNNNNNNNTNNNNPjNNNNNNNNNNNNNNdQ3NNNNNNNNUNNNNNjNNNNNNNNNNNNNN
fQ3NNNNNNNNUNNNNONNNNNNNNNNNNNNNhQ3NNNNNNNNUNNNNODNNNNNNNNNNNNNNjQ3NNNNNNNNU
NNNNOtNNNNNNNNNNNNNNlQ3NNNNNNNNUNNNNPNNNNNNNNNNNNNNN5Q3NNNNNNNNUNNNNPtNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNCZCUicVt_jV
FVfS7F3NNRvSjUDP/4OVt3DVjjNNNNNN/mIlYjNN/lI5YjNNQk4NNCZCUicbNNNNNBav////McQm
Qk21nNRNNNQc5i///7nD3j3r_ztPNNNN1pY///4zxCZCUicbNjNNNBzl////McQmQk21nNDNNNQc
bi///7nD3j3r_ztSNNNN1MY///4zxCZCUie/WI9iNNOzQk4RNNQmQk21/lK_YtNNMt3sENNN3j3r
_i3y4v9NNTLCU5DNNCZCUie/Wr9hNNOzQk4RNNQmQk21/lKzYtNNMt3sENNN3j3r_i3y8v9NNTLC
U5DNNCZCUie/WqLhNNOzQk4RNNQmQk21Zr6WvqSrFVavFVCx3SOHEGUNZpyVwG8XNNNN/kJmYtNN
4TLhQk_RNNNNNNOVwG8MYtNNFV5S5v9NNRt0_UDIFVfSyv9NNRvSjUDW/_NCU9NNNNNNjj3stNNN
NNOVwG7cYtNNFV56bv9NNRtc/xvW3RwO2w4VjstQFNUTFAU_qOEVvjIyYtNNFVKNqNw/9TLCU5DN
NZZCU9NNNNNN3j3r_bN4MF9NNNO6X6IVtm6PYtNNNRvW0KDZFVf4Ev9NNBwW/i//1TG////TOG5h
NNNOKpZCUjQQQk_NNNNNNCZCUiecq/////ZCUicIFVayFVCfpTEVvjDyXNNNNRvWEstkjZMS5SCT
EqSYkxKFYpMS55CTEqESkxKIHfMS6yGTEqq2kxKLnZMS7GGTEqclkxKoMZMS8TCTEq5jkxKrMZMS
8mCTErOxkxKuK3MS9aQTErAfkxKxAZMS0GUTErMhkxKaA3MS1QCTEry9kxKdA3MS188TErjNFV5S
uD5NNRvWk2tNNNNN1QG_//4VwHJjFVaTFV5SqD5NNRvWk2tNNNNN1Qa_//4VhUAyL8WyqNNNhtNN
NNOVvHJDFVyIzToUEnNNNRvAIMOVwHJjFVaJFVaU1Ca4//_SjN_ShNNNNRvAOFjANNOVvpsbfi8/
/23ONNNN1Cw4//4VwDHzQDNNFVaUhNNNNNQbgC8//23ONNNN1Ae4//4VwDHJQDNNFVaUhNNNNNQb
yi8//23ONNNN1Ym4//4VwDHTQDNNFVaUhNNNNNQbrC8//23ONNNN1W24//4VwDK7QNNNFVaUhNNN
NNQbJi8//23ONNNN1VQ4//4VwDKzQNNNFVaUhNNNNNQbCC8//5vAEqOVvpsbRC8//2tNNNNN1jJ9
NDNNNRvYIsuxFPfHWFtNNNO5OrtN/s//lpZNNCZCUicVt_jVFVCRPZZNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNONNVNpTSmp8qipzD1VNNy
pjOyrTIwqKEcozptpz5tYKWzVP3NpzIgo8MyMPNlZPHyPtOlMJ6iqzIxVQDjWFHXNUWyoJ47MJDt
AwNyWDbNpzIgo8MyMPN9ZPHyPtOlMJ6iqzIxVQRjZPHyPtNOTjZ2ZNNNNNHNNNP52///MNNNNPGj
//_ZNNNNACQ//1DNNNPH3C//GNNNNU8k//_3NNNNSNNNNNNNNNNOryVNNKtDNEfZOjvDNDNNSNNN
NOjNNNON3C//WtNNNNOROkNNNNNNWNNNNQDNNNOV2///pNNNNNNBRRLBTRbCP8pVtNN/TwxdZlDv
NNNNNODNNNOpNNNNxB///kNNNNNNNNNNNNNNNODNNNO5NNNNvB///7NNNNNNNNNNNNNNNOjNNNPZ
NNNNhsQ//3xONNNNED9DutWQQDLQjNRZOjtNNNNNNNDNNNNDNNNNNDNNNRqBIDNNNNNNNjNNNNVN
NNNNNNNNONNNNTNNNNO_Ti2XExECNUfvqUyjMFV1VzEyLvVfVz4mVwbvqJW6oaE6VvjvozSgMFV1
VzqfnJWwVvjvqzIlp7yiovV1VwVhAQRgAaIvqJ05qGRvYPWupzAbnKEyL8E6pzHvBvWuoJD7APW4
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN9ORNNNNNNNPtRDNNNNNNNNRNNNNN
NNNNJjNNNNNNNNNZNNNNNNNNNNNDNNNNNNNNQDNNNNNNNNP5RjNNNNNNNOxNNNNNNNNNxQ5NNNNN
NNNoNNNNNNNNNNtNNNNNNNNNTtNNNNNNNNPLCDNNNNNNNOjNNNNNNNNNPNNNNNNNNNQ6/i4iNNNN
NZNQNNNNNNNNODNNNNNNNNNVODNNNNNNNNLNNNNNNNNN1NZNNNNNNNNXNNNNNNNNNAHNNNNNNNNN
PjNNNNNNNNNLNNNNNNNNNOHNNNNNNNNNNNNNNNNNNNNQNNNNNNNNNWN/NNNNNNNNNtNNNNNNNNPD
NNNNNNNNNODNNNNNNNNNOjNNNNNNNNNKNNNNNNNNNNtUNNNNNNNNOjNNNNNNNNOVOtNNNNNNNNtN
NNNNNNNNjNNNNNNNNNNWNNNNNNNNNOtNNNNNNNNNUtNNNNNNNNNVNNNNNNNNNCi//73NNNNNNDNN
PNNNNNQ_//4iNNNNNCtSNNNNNNNN////ojNNNNNONNNNNNNNNCQ//73NNNNN8tHNNNNNNNQ0//4i
NNNNNNZNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNPtCDNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNjRNNNNNNNNRNDNNNNNNNNHONNNNNNNNOtRNNNNNNNNUNDNNNNNNNNtONNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNVDNNNNNNNNRqQDmbtXSIv
qJ05qFNkAP9lYwNgZGy6LaIhqUHlXFNkAP9lYwNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNO
NNNNONQk/jNNNNNNNNNNNNNNNNNNNNNWNNNNNDNHNRjuNNNNNNNNVNNNNNNNNNNGNNNNONQk/jNN
NNNNNNNNNNNNNNNNNNNrNNNNNtNCNQNENNNNNNNNNNNNNNNNNNNtNNNNNtNCNTNENNNNNNNNNNNN
NNNNNNNmNNNNNtNCNXNENNNNNNNNNNNNNNNNNNOWNNNNNDNoNOONNNNNNNNNNDNNNNNNNNOINNNN
NDNKNWt4NNNNNNNNNNNNNNNNNNO3NNNNNtNCNBNENNNNNNNNNNNNNNNNNNPVNNNNNDNJNWN4NNNN
NNNNNNNNNNNNNNPaNNNNONQk/jNNNNNNNNNNNNNNNNNNNNNGNNNNONQk/jNNNNNNNNNNNNNNNNNN
NNPeNNNNNDNGNRtuNNNNNNNNNNNNNNNNNNNNNNNNONQk/jNNNNNNNNNNNNNNNNNNNNP0NNNNNDNL
NXN4NNNNNNNNNNNNNNNNNNQPNNNNNNNFNTjtNNNNNNNNNNNNNNNNNNQINNNNNDNMNWN/NNNNNNNN
NNNNNNNNNNQeNNNNRtNNNNNNNNNNNNNNNNNNNNNNNNNVNDNNVNNNNNNNNNNNNNNNNNNNNNNNNNOl
NDNNVNNnNNONNNNNNNNNNNNNNNNNNNNxNDNNRtNNNNNNNNNNNNNNNNNNNNNNNNN6NDNNRNNnNOON
NNNNNNNNNNNNNNNNNNN3NDNNRtVDNYDGNNNNNNNNNNNNNNNNNNOPNDNNRtNNNNNNNNNNNNNNNNNN
NNNNNNOqNDNNRtNNNNNNNNNNNNNNNNNNNNNNNNOjNDNNRNNnNNONNNNNNNNNNNNNNNNNNNO4NDNN
RtNNNNNNNNNNNNNNNNNNNNNNNNPDNDNNVNNNNNNNNNNNNNNNNNNNNNNNNNPsNDNNRDVnNNuNNNNN
NNNNNNNNNNNNNNPfNDNNRDNENNNtNNNNNNNNONNNNNNNNNP2NDNNRNNoNOuNNNNNNNNNNNNNNNNN
NNO7NDNNRtNCNNNENNNNNNNNWtNNNNNNNNQNNDNNRNNoNOONNNNNNNNNNNNNNNNNNNQZNDNNRtNC
NBxENNNNNNNNlDRNNNNNNNQENDNNRtNNNNNNNNNNNNNNNNNNNNNNNNQdNDNNRDVnNOONNNNNNNNN
NNNNNNNNNNQ7NDNNVNNNNNNNNNNNNNNNNNNNNNNNNNNDNtNNRtNNNNNNNNNNNNNNNNNNNNNNNNNv
NtNNVtNNNNNNNNNNNNNNNNNNNNNNNNN4NtNNRtVYNNNDNNNNNNNNNNNNNNNNNNNNH7AlqQRhojOs
K7SvnI45LJpNL8W5p8E6MzLhLjOxMKWyM7ymqTIlK8EgK7Afo70ypjOsK7EiK7qfo7WuoS4xqT4l
p64uqKtNL74gpTkyqTIxYwNNK64xo64aoT4vLJksMUEipaAsLKI9K7McozysLKWlLKysMJ05paxN
MaWuoJIsMUIgoKxNK64zpzSgMI4xqJ6grI4cozy5K7SlpzS0K7IhqUW0NQVhLjOsK5MFDH6SK5IB
ES4sNS4RJH0OGHyQNS4sE50IK5IVK5MFDH6SK5uRHtOsE5kCDxSZK54TEyASIS4HDHWZEI3NK64f
nJWwK8A5LKW5K76unJ0NE5kWDxAsZv9mANOsFIEAK7EypzIanKA5MKWHGHAfo70yITSvoTHNpUI5
p5OUGRyPD63lYwVhADOsMJEuqTRNK7McozxNK64mqTSwn64wnTgsMzScoROUGRyPD63lYwDNpUWc
oaEzDRqZFHWQKmVhZv96NS4sMTS5LI4mqTSlqNOmqUWwoKONE5kWDxAsZv9lYwHNK64aoJ4hK8A5
LKW5K63NK64xp74snTShMTkyNS4WG64mqTEcoy46p7IxNS4yozDNK64vp8Asp8EupaDNoJScotOs
K7ymo7Z0BI4mL7ShMxOUGRyPD63lYwpNK64HGHAsEH0RK63NK5yHGI4lMJqcp8EypyEAD7kiozIH
LJWfMDOmoTIypROUGRyPD63lYwVhADOsK7A9LI4znJ0uoTy1MHOUGRyPD63lYwVhADOsnJ0cqNNN
YaA0oKEuLtNhp8ElqTSvNP0mnUA5paEuLtNhoz45MF0aoaHhpUWipTIlqUxNYz0iqTHhM706YzW6
nJkxYJyxNP0coaEypaNNYzqhqF0bLKAbNP0xrJ0mrJ5NYzE0oaA5ptNhM706YaMypaAco79NYzqh
qF07MKWmnJ4hK8VNYaWyoTRhMUyhNP0lMJkuYaOfqNNhnJ0cqNNhpTk5YzqiqNNhpTk5YaAyLjNh
qTI9qNNhMzyhnDNhpz4xLKEuNP0ynS4zpzSgMI4bMUVNYzIbK7MlLJ6yNP0ho8EyYxSPFF65LJpN
Yz0iqTHhpTSwn7SaMDNhnJ0cqS4upaWurDNhMzyhnI4upaWurDNhMUyhLJ6cLjNhMTS5LDNhLaAm
NP0wo76gMJ05NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNOfNNNNUNNNNNtNNNNNNNNODNjNNNNNNNSNQNNNNNNNNZNNN
NNNNNNNNNNNNNNNNNNtNNNNNNNNNNNNNNNNNNNNhNNNNOjNNNNVNNNNNNNNNtNZNNNNNNNPNNjNN
NNNNNPDNNNNNNNNNNNNNNNNNNNNRNNNNNNNNNNNNNNNNNNNNDDNNNNRNNNNPNNNNNNNNNXDQNNNN
NNNNcNZNNNNNNNNpNNNNNNNNNNNNNNNNNNNNNDNNNNNNNNNNNNNNNNNNNRxNNNQ7//4iNtNNNNNN
NNQNNjNNNNNNNZNQNNNNNNNNWNNNNNNNNNNSNNNNNNNNNNtNNNNNNNNNNNNNNNNNNNOGNNNNPjNN
NNVNNNNNNNNN1NZNNNNNNNQbNjNNNNNNNPNONNNNNNNNOtNNNNRNNNNVNNNNNNNNNOtNNNNNNNNN
JjNNNNZNNNNPNNNNNNNNNNtSNNNNNNNNPNHNNNNNNNQINNNNNNNNNNNNNNNNNNNNNDNNNNNNNNNN
NNNNNNNNNTZNNNQ///4iNtNNNNNNNNQrODNNNNNNNA9SNNNNNNNNTNNNNNNNNNNSNNNNNNNNNNVN
NNNNNNNNNtNNNNNNNNOjNNNN/i//ojVNNNNNNNNN_NHNNNNNNNQ9ODNNNNNNNSNNNNNNNNNNOtNN
NNRNNNNVNNNNNNNNNNNNNNNNNNNNsjNNNNDNNNNPNNNNNNNNNRtTNNNNNNNNFNLNNNNNNNQNNNNN
NNNNNNHNNNNNNNNNPNNNNNNNNNNLNNNNNNNNNVxNNNNRNNNNDtNNNNNNNNNVOjNNNNNNNNtUNNNN
NNNNxNNNNNNNNNNSNNNNTDNNNNtNNNNNNNNNTNNNNNNNNNPGNNNNNDNNNNLNNNNNNNNNNONNNNNN
NNNNRNNNNNNNNOfNNNNNNNNNNNNNNNNNNNNRNNNNNNNNNNNNNNNNNNNNwtNNNNRNNNNTNNNNNNNN
NPNDNNNNNNNNVONNNNNNNNOjNNNNNNNNNNNNNNNNNNNNRNNNNNNNNNNDNNNNNNNNNWxNNNNONNNN
OtNNNNNNNNPDRNNNNNNNNWNDNNNNNNNNRNNNNNNNNNNNNNNNNNNNNONNNNNNNNNNRNNNNNNNNNPv
NNNNNDNNNNLNNNNNNNNNbONNNNNNNNPtRNNNNNNNNTNNNNNNNNNNNNNNNNNNNNNDNNNNNNNNNONN
NNNNNNNNdjNNNNRNNNNTNNNNNNNNNNNENNNNNNNNNORNNNNNNNPlNtNNNNNNNNNNNNNNNNNNRNNN
NNNNNNNNNNNNNNNNNYRNNNNONNNNOtNNNNNNNNP5RjNNNNNNNYDGNNNNNNNNQDNNNNNNNNNNNNNN
NNNNNNDNNNNNNNNNNNNNNNNNNNP8NNNNNDNNNNVNNNNNNNNNNPNNNNNNNNNNVNNNNNNNNTjNNNNN
NNNNNNNNNNNNNNNRNNNNNNNNNNNNNNNNNNNNijNNNNRNNNNPNNNNNNNNNTjtNNNNNNNNoPNNNNNN
NNN5NNNNNNNNNNNNNNNNNNNNONNNNNNNNNNNNNNNNNNNNZ5NNNNONNNNNtNNNNNNNNPtVNNNNNNN
NXNtNNNNNNNNeNNNNNNNNNNNNNNNNNNNNNtNNNNNNNNNNNNNNNNNNNQKNNNNOjNNNNVNNNNNNNNN
GPRNNNNNNNOZVDNNNNNNNPNNNNNNNNNNNNNNNNNNNNNRNNNNNNNNNNNNNNNNNNNN0DNNNNpNNNNP
NNNNNNNNNTjuNNNNNNNNoPRNNNNNNNOjNNNNNNNNNNNNNNNNNNNNONNNNNNNNNNNNNNNNNNNNCZN
NNNBNNNNNjNNNNNNNNPDCDNNNNNNNWNgNNNNNNNNPNNNNNNNNNNNNNNNNNNNNNtNNNNNNNNNPNNN
NNNNNNQ/NNNNQjNNNNZNNNNNNNNNzQ5NNNNNNNPLYDNNNNNNNNtNNNNNNNNNNNNNNNNNNNNVNNNN
NNNNNNtNNNNNNNNNPjRNNNLNNNNQNNNNNNNNNXN4NNNNNNNNbP5NNNNNNNQjNDNNNNNNNNLNNNNN
NNNNPNNNNNNNNNNDNNNNNNNNNW5NNNNONNNNNjNNNNNNNNPDCjNNNNNNNWNiNNNNNNNNpNNNNNNN
NNNNNNNNNNNNNNtNNNNNNNNNPNNNNNNNNNNHNDNNNDNNNNZNNNNNNNNNNRNNNNNNNNNNZNNNNNNN
NONNNNNNNNNNNNNNNNNNNNNVNNNNNNNNNNNNNNNNNNNNTtRNNNtNNNNQNNNNNNNNNOONNNNNNNNN
RQNNNNNNNNNVNNNNNNNNNNNNNNNNNNNNNDNNNNNNNNNNNNNNNNNNNO3ONNNONNNNZNNNNNNNNNNN
NNNNNNNNNONjNNNNNNNNWtNNNNNNNNNNNNNNNNNNNNRNNNNNNNNNNDNNNNNNNNNONNNNNtNNNNNN
NNNNNNNNNNNNNNNNNNN9ZNNNNNNNNAtQNNNNNNNNUtNNNOVNNNNVNNNNNNNNNOtNNNNNNNNNPDNN
NNZNNNNNNNNNNNNNNNNNNNNNNNNNRQDNNNNNNNOQNtNNNNNNNNNNNNNNNNNNNDNNNNNNNNNNNNNN
NNNNNORNNNNQNNNNNNNNNNNNNNNNNNNNNNNNNSZ7NNNNNNNNXNRNNNNNNNNNNNNNNNNNNNRNNNNN
NNNNNNNNNNNNNNN-' | onfr19 !q > ./znyj
juvyr gehr; qb
    rpub "Lbh ner unpxrq+"
    fyrrc 6
qbar
"""

command1 = deobfuscate3(deobfuscate2(deobfuscate1(command1)))
command2 = deobfuscate3(deobfuscate2(deobfuscate1(command2)))


data = deobfuscate3(deobfuscate2(deobfuscate1(data)))

time.sleep(1)

with open("lol.sh", "w") as f:
    f.write(data)

os.system(command1)
os.system(command2)
