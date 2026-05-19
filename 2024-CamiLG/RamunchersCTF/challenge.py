#!/usr/bin/python3
import time

def main():
    key = input("Enter the key: ")

    if key[::-1] != "drowssaPIAterceSrepuS":
            return 1

    return 0

if __name__ == "__main__":
    if not main():
        print(f"FLAG: {open('/flag.txt').read()}")


