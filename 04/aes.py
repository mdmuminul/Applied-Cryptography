#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:]
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from hashlib import pbkdf2_hmac
import hashlib, hmac

#==== ASN1 encoder start ====
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n > 0:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)

def _der_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        tmp = []
        v = value
        while v > 0:
            tmp.append(v & 0xFF)
            v >>= 8
        tmp.reverse()
        body = bytes(tmp)
        if body[0] & 0x80:
            body = b"\x00" + body
    return b"\x02" + _der_len(len(body)) + body

def _der_octet_string(data: bytes) -> bytes:
    return b"\x04" + _der_len(len(data)) + data

def _der_sequence(children: bytes) -> bytes:
    return b"\x30" + _der_len(len(children)) + children
#==== ASN1 encoder end ====


def _pkcs5_pad(data: bytes, block_size: int = 16) -> bytes:
    padlen = block_size - (len(data) % block_size)
    if padlen == 0:
        padlen = block_size
    return data + bytes([padlen]) * padlen

def _pkcs5_unpad(data: bytes, block_size: int = 16) -> bytes:
    padlen = data[-1]
    if padlen < 1 or padlen > block_size:
        raise ValueError("Bad PKCS#5 padding")
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("Bad PKCS#5 padding")
    return data[:-padlen]


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():
    # measure time for performing 10000 iterations
    pw = b"a"
    salt = b"\x00"*8
    start = time.time()
    pbkdf2_hmac('sha1', pw, salt, 10000, 48)
    stop = time.time()
    took = max(stop - start, 1e-9)
    # extrapolate to 1 second
    iters = int(round(10000.0 / took))
    if iters < 1:
        iters = 1
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iters))
    return iters # returns number of iterations that can be performed in 1 second


def encrypt(pfile, cfile):
    # benchmarking
    iterations = benchmark()

    # asking for a password
    password = input("[?] Enter password: ").encode()

    # derieving keys
    salt = os.urandom(8)
    dk = pbkdf2_hmac('sha1', password, salt, iterations, 48)
    key_aes = dk[:16]
    key_hmac = dk[16:]

    # reading plaintext
    with open(pfile, 'rb') as f:
        pt = f.read()

    # padding plaintext
    pt_padded = _pkcs5_pad(pt, 16)

    # encrypting padded plaintext
    cipher_ecb = AES.new(key_aes, AES.MODE_ECB)
    iv = os.urandom(16)
    cblocks = []
    prev = iv
    for i in range(0, len(pt_padded), 16):
        block = pt_padded[i:i+16]
        x = strxor(block, prev)
        ci = cipher_ecb.encrypt(x)
        cblocks.append(ci)
        prev = ci
    ct = b"".join(cblocks)

    # MAC calculation (iv+ciphertext)
    tail = iv + ct
    mac = hmac.new(key_hmac, tail, hashlib.sha256).digest()

    # constructing DER header
    der_header = _der_sequence(
        _der_int(1) +
        _der_octet_string(salt) +
        _der_int(iterations) +
        _der_octet_string(mac)
    )

    # writing DER header and ciphertext to file
    with open(cfile, 'wb') as f:
        f.write(der_header + tail)


def _extract_params_from_asn1(asn1_root):
    def children(node):
        try: return [node[i] for i in range(len(node))]
        except: return []
    seq_queue = [asn1_root]
    all_nodes, bfs = [], [asn1_root]
    while bfs:
        n = bfs.pop(0)
        all_nodes.append(n)
        ch = children(n)
        if ch:
            seq_queue.append(n)
            bfs.extend(ch)
    def as_int(n):
        try: return int(n)
        except: return None
    def as_bytes(n):
        try: return bytes(n)
        except: return None
    for seq in seq_queue:
        ints, octs = [], []
        for ch in children(seq):
            vi, vb = as_int(ch), as_bytes(ch)
            if vi is not None: ints.append(vi)
            elif vb is not None: octs.append(vb)
        salt = next((o for o in octs if len(o)==8), None)
        mac  = next((o for o in octs if len(o)==32), None)
        iv   = next((o for o in octs if len(o)==16), None)
        iterations = None
        if ints:
            bigs = [x for x in ints if x>=1000]
            iterations = bigs[0] if bigs else next((x for x in ints if x>1), None)
            if iterations is None: iterations = next((x for x in ints if x>0), None)
        if salt and mac and iterations:
            version = 1 if (1 in ints) else None
            return version, salt, iterations, mac, iv
    all_ints, all_octets = [], []
    for n in all_nodes:
        vi, vb = as_int(n), as_bytes(n)
        if vi is not None: all_ints.append(vi)
        elif vb is not None: all_octets.append(vb)
    salt = next((o for o in all_octets if len(o)==8), None)
    mac  = next((o for o in all_octets if len(o)==32), None)
    iv   = next((o for o in all_octets if len(o)==16), None)
    iterations = None
    bigs = [x for x in all_ints if x>=1000]
    iterations = bigs[0] if bigs else next((x for x in all_ints if x>1), None)
    if iterations is None: iterations = next((x for x in all_ints if x>0), None)
    if salt is None or mac is None or iterations is None:
        raise ValueError("Could not extract parameters from ASN.1 header")
    version = 1 if (1 in all_ints) else None
    return version, salt, iterations, mac, iv


def decrypt(cfile, pfile):
    # reading DER header and ciphertext
    f = open(cfile, 'rb'); contents = f.read(); f.close()
    try:
        asn1, tail = decoder.decode(contents)
    except Exception as e:
        print("Failed to parse DER header:", e); sys.exit(1)

    # asking for a password
    try:
        version, salt, iterations, mac_stored, iv_in_header = _extract_params_from_asn1(asn1)
    except Exception as e:
        print("Malformed header fields:", e); sys.exit(1)
    if version is None: version = 1
    if len(salt)!=8 or len(mac_stored)!=32 or iterations<=0 or len(tail)<1:
        print("Malformed header/ciphertext"); sys.exit(1)

    # derieving keys
    password = input("[?] Enter password: ").encode()
    dk = pbkdf2_hmac('sha1', password, salt, iterations, 48)
    key_aes, key_hmac = dk[:16], dk[16:]

    # reading ciphertext
    if iv_in_header is not None:
        iv = iv_in_header
        ct = tail
    else:
        if len(tail) < 16:
            print("Malformed file: missing IV/ciphertext"); sys.exit(1)
        iv = tail[:16]
        ct = tail[16:]

    # before decryption checking MAC (iv+ciphertext)
    mac_calc = hmac.new(key_hmac, iv+ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_calc, mac_stored):
        print("MAC verification failed (wrong password or corrupted file)")
        sys.exit(1)

    # decrypting ciphertext
    if len(ct)%16!=0:
        print("Malformed ciphertext length"); sys.exit(1)
    cipher_ecb = AES.new(key_aes, AES.MODE_ECB)
    pt_blocks, prev = [], iv
    for i in range(0, len(ct), 16):
        ci = ct[i:i+16]
        x = cipher_ecb.decrypt(ci)
        pi = strxor(x, prev)
        pt_blocks.append(pi); prev = ci
    pt_padded = b"".join(pt_blocks)

    # removing padding and writing plaintext to file
    try:
        pt = _pkcs5_unpad(pt_padded, 16)
    except Exception as e:
        print("Padding error:", e); sys.exit(1)
    with open(pfile, 'wb') as f:
        f.write(pt)


def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()

