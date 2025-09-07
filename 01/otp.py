#!/usr/bin/env python3

import os, sys

def bi(b):
    i = 0
    for x in b:
        i = (i << 8) | (x & 0xFF)
    return i

def ib(i, length):
    if length == 0:
        return b''
    out = []
    for _ in range(length):
        out.append(i & 0xFF)
        i >>= 8
    out.reverse()
    return bytes(out)

def encrypt(pfile, kfile, cfile):
    try:
        with open(pfile, 'rb') as f:
            plaintext_bytes = f.read()
    except Exception:
        print("Error: Can't read the plaintext")
        sys.exit(1)

    key_bytes = os.urandom(len(plaintext_bytes))
    plaintext_int = bi(plaintext_bytes)
    key_int = bi(key_bytes)
    ciphertext_int = plaintext_int ^ key_int
    ciphertext_bytes = ib(ciphertext_int, len(plaintext_bytes))

    try:
        with open(kfile, 'wb') as file_key:
            file_key.write(key_bytes)
        with open(cfile, 'wb') as file_ciphertext:
            file_ciphertext.write(ciphertext_bytes)
    except Exception:
        print("Error: Can't write the output")
        sys.exit(1)

def decrypt(cfile, kfile, pfile):
    try:
        with open(cfile, 'rb') as file_ciphertext:
            ciphertext_bytes = file_ciphertext.read()
        with open(kfile, 'rb') as file_key:
            key_bytes = file_key.read()
    except Exception:
        print("Error: Can't read the input")
        sys.exit(1)

    if len(ciphertext_bytes) != len(key_bytes):
        print("Error: The ciphertext and key length are not the same")
        sys.exit(1)

    ciphertext_int = bi(ciphertext_bytes)
    key_int = bi(key_bytes)
    plaintext_int = ciphertext_int ^ key_int
    plaintext_bytes = ib(plaintext_int, len(ciphertext_bytes))

    try:
        with open(pfile, 'wb') as file_plaintext:
            file_plaintext.write(plaintext_bytes)
    except Exception:
        print("Error: Can't write the plaintext")
        sys.exit(1)

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
