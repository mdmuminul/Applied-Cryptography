#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from secp256r1 import curve
from pyasn1.codec.der import decoder

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
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- asn1 DER encoder
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = ib(n)
    return bytes([0x80 | len(b)]) + b

def _der_int(x):
    if x == 0:
        body = b'\x00'
    else:
        body = ib(x)
        if body[0] & 0x80:
            body = b'\x00' + body
    return b'\x02' + _der_len(len(body)) + body

def _der_seq(content):
    return b'\x30' + _der_len(len(content)) + content
# --------------- asn1 DER encoder end


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    data = open(filename, 'rb').read()
    der = pem_to_der(data)
    pkcs8, _ = decoder.decode(der)
    ecpriv_der = pkcs8.getComponentByPosition(2).asOctets()
    ecpriv, _ = decoder.decode(ecpriv_der)
    d_bytes = ecpriv.getComponentByPosition(1).asOctets()
    d = bi(d_bytes)
    return d

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    data = open(filename, 'rb').read()
    der = pem_to_der(data)
    spki, _ = decoder.decode(der)
    bitstr = spki.getComponentByPosition(1)
    pt = bitstr.asOctets()
    if len(pt) >= 1 and pt[0] == 0x00:
        pt = pt[1:]
    if not pt:
        raise ValueError
    if pt[0] == 0x04:
        if len(pt) != 65:
            raise ValueError
        x = bi(pt[1:33])
        y = bi(pt[33:65])
        P = [x, y]
    elif pt[0] in (0x02, 0x03):
        P = curve.decompress(pt)
    else:
        raise ValueError
    if not curve.valid(P):
        raise ValueError
    return (P[0], P[1])

def ecdsa_sign(keyfile, filetosign, signaturefile):

    # get the private key
    d = get_privkey(keyfile)

    # calculate SHA-384 hash of the file to be signed
    m = open(filetosign,'rb').read()
    h384 = hashlib.sha384(m).digest()

    # truncate the hash value to the curve size
    h_trunc = h384[:32]

    # convert hash to integer
    h = bi(h_trunc)

    # generate a random nonce k in the range [1, n-1]
    n = curve.n
    while True:
        k = bi(os.urandom(32)) % n
        if 1 <= k < n:
            R = curve.mul(curve.g, k)
            r = R[0] % n
            if r != 0:
                kinv = pow(k, -1, n)
                s = (kinv * (h + r * d)) % n
                if s != 0:
                    break

    # calculate ECDSA signature components r and s
    r_bytes = _der_int(r)
    s_bytes = _der_int(s)

    # DER-encode r and s
    sig_der = _der_seq(r_bytes + s_bytes)

    # write DER structure to file
    with open(signaturefile, 'wb') as f:
        f.write(sig_der)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    try:
        Qx, Qy = get_pubkey(keyfile)
        Q = [Qx, Qy]
        if not curve.valid(Q):
            print("Verification failure"); return
        sig_der = open(signaturefile,'rb').read()
        seq, _ = decoder.decode(sig_der)
        r = int(seq.getComponentByPosition(0))
        s = int(seq.getComponentByPosition(1))
        n = curve.n
        if not (1 <= r < n and 1 <= s < n):
            print("Verification failure"); return
        m = open(filetoverify,'rb').read()
        h = bi(hashlib.sha384(m).digest()[:32])
        w = pow(s, -1, n)
        u1 = (h * w) % n
        u2 = (r * w) % n
        R = curve.add(curve.mul(curve.g, u1), curve.mul(Q, u2))
        if R[0] is not None and (R[0] % n) == r:
            print("Verified OK")
        else:
            print("Verification failure")
    except Exception:
        print("Verification failure")

def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()

