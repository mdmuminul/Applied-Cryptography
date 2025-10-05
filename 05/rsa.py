#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took x.y hours (please specify here how much time your solution required)


def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

#==== ASN1 encoder start ====
# put your DER encoder functions here
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    s = ib(n)
    return bytes([0x80 | len(s)]) + s

def _der_tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content

def der_null():
    return _der_tlv(0x05, b'')

def der_octet_string(data):
    return _der_tlv(0x04, data)

def der_sequence(content):
    return _der_tlv(0x30, content)

def der_oid_from_dotted(dotted):
    parts = [int(x) for x in dotted.split('.')]
    first = 40*parts[0] + parts[1]
    out = bytes([first])
    for p in parts[2:]:
        if p == 0:
            out += b'\x00'
        else:
            tmp = []
            while p > 0:
                tmp.append(p & 0x7f)
                p >>= 7
            for i in range(len(tmp)-1, -1, -1):
                v = tmp[i]
                out += bytes([(0x80|v) if i!=0 else v])
    return _der_tlv(0x06, out)
#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content to DER
    if content.startswith(b'-----BEGIN'):
        lines = content.splitlines()
        body = b''.join(ln for ln in lines if not ln.startswith(b'-----') and ln.strip())
        return codecs.decode(body, 'base64')
    return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)

    data = open(filename, 'rb').read()
    der = pem_to_der(data)

    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    spki, _ = decoder.decode(der)

    # convert BITSTRING to bytestring
    bitstr = spki[1]
    bs = bytes(bitstr.asOctets())
    if len(bs) == 0:
        raise ValueError('bad public key bitstring')

    # DER-decode the bytestring (which is actually DER) and return (N, e)
    # If the first byte is 0x00, drop it (unused-bits count); otherwise decode as-is.
    inner = bs[1:] if bs[0] == 0x00 and len(bs) > 1 else bs
    pubkey, _ = decoder.decode(inner)
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)

    data = open(filename, 'rb').read()
    der = pem_to_der(data)

    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    p8, _ = decoder.decode(der)
    inner = bytes(p8[2].asOctets())

    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey, _ = decoder.decode(inner)
    return int(privkey[1]), int(privkey[3])


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate number of bytes required to represent the modulus N
    k = (n.bit_length()+7)//8

    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) > k - 11:
        raise ValueError('message too long')

    # generate padding bytes
    ps_len = k - 3 - len(plaintext)
    ps = b''
    while len(ps) < ps_len:
        chunk = os.urandom(ps_len - len(ps))
        chunk = bytes([b for b in chunk if b != 0x00])
        ps += chunk
    return b'\x00\x02' + ps + b'\x00' + plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate bytelength of modulus N
    k = (n.bit_length()+7)//8

    # plaintext must be at least 11 bytes smaller than the modulus N
    if len(plaintext) > k - 11:
        raise ValueError('message too long')

    # generate padding bytes
    ps_len = k - 3 - len(plaintext)
    ps = b'\xff' * ps_len
    return b'\x00\x01' + ps + b'\x00' + plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding

    if len(plaintext) < 11 or plaintext[0] != 0x00:
        return b''
    bt = plaintext[1]
    i = 2
    ps_count = 0
    if bt == 0x02:
        while i < len(plaintext) and plaintext[i] != 0x00:
            if plaintext[i] == 0x00:
                return b''
            ps_count += 1
            i += 1
        if i >= len(plaintext) or plaintext[i] != 0x00 or ps_count < 8:
            return b''
        return plaintext[i+1:]
    elif bt == 0x01:
        while i < len(plaintext) and plaintext[i] != 0x00:
            if plaintext[i] != 0xff:
                return b''
            ps_count += 1
            i += 1
        if i >= len(plaintext) or plaintext[i] != 0x00 or ps_count < 8:
            return b''
        return plaintext[i+1:]
    else:
        return b''

def encrypt(keyfile, plaintextfile, ciphertextfile):
    N, e = get_pubkey(keyfile)
    k = (N.bit_length()+7)//8
    D = open(plaintextfile, 'rb').read()
    EM = pkcsv15pad_encrypt(D, N)
    m = bi(EM)
    c = pow(m, e, N)
    C = ib(c, length=k)
    open(ciphertextfile, 'wb').write(C)

def decrypt(keyfile, ciphertextfile, plaintextfile):
    N, d = get_privkey(keyfile)
    k = (N.bit_length()+7)//8
    C = open(ciphertextfile, 'rb').read()
    if len(C) != k:
        raise ValueError('ciphertext length mismatch')
    c = bi(C)
    m = pow(c, d, N)
    EM = ib(m, length=k)
    D = pkcsv15pad_remove(EM)
    if D == b'':
        raise ValueError('decryption error')
    open(plaintextfile, 'wb').write(D)

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    data = open(filename, 'rb').read()
    h = hashlib.sha256(data).digest()
    oid_sha256 = der_oid_from_dotted('2.16.840.1.101.3.4.2.1')
    algid = der_sequence(oid_sha256 + der_null())
    return der_sequence(algid + der_octet_string(h))

def sign(keyfile, filetosign, signaturefile):
    N, d = get_privkey(keyfile)
    k = (N.bit_length()+7)//8
    T = digestinfo_der(filetosign)
    EM = pkcsv15pad_sign(T, N)
    m = bi(EM)
    s = pow(m, d, N)
    S = ib(s, length=k)
    open(signaturefile, 'wb').write(S)

    # Warning: make sure that signaturefile produced has the same
    # length as the modulus (hint: use parametrized ib()).

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    N, e = get_pubkey(keyfile)
    k = (N.bit_length()+7)//8
    S = open(signaturefile, 'rb').read()
    if len(S) != k:
        print("Verification failure")
        return
    s = bi(S)
    m = pow(s, e, N)
    EM = ib(m, length=k)
    T = pkcsv15pad_remove(EM)
    if T == b'':
        print("Verification failure")
        return
    T2 = digestinfo_der(filetoverify)
    if T == T2:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()

