#!/usr/bin/env python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:]
import hmac

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)

def _b128(n):
    if n == 0:
        return b"\x00"
    parts = []
    while n:
        parts.append(n & 0x7F)
        n >>= 7
    parts.reverse()
    for i in range(len(parts) - 1):
        parts[i] |= 0x80
    return bytes(parts)

def der_oid(dotted):
    arcs = [int(x) for x in dotted.split(".")]
    head = bytes([40 * arcs[0] + arcs[1]])
    tail = b"".join(_b128(x) for x in arcs[2:])
    body = head + tail
    return b"\x06" + _der_len(len(body)) + body

def der_null():
    return b"\x05\x00"

def der_octets(data):
    return b"\x04" + _der_len(len(data)) + data

def der_seq(payload):
    return b"\x30" + _der_len(len(payload)) + payload

def encode_digestinfo(oid, digest):
    algid = der_seq(der_oid(oid) + der_null())
    return der_seq(algid + der_octets(digest))

OIDS = {
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
}
OID_TO_HASH = {v: k for k, v in OIDS.items()}

def hmac_file(path, key, hashname="sha256", chunk=512):
    hm = hmac.new(key, None, getattr(hashlib, hashname))
    with open(path, "rb") as f:
        while (c := f.read(chunk)):
            hm.update(c)
    return hm.digest()

def mac(filename):
    key = input("[?] Enter key: ").encode()
    digest = hmac_file(filename, key, "sha256")
    print("[+] Calculated HMAC-SHA256:", digest.hex())
    der = encode_digestinfo(OIDS["sha256"], digest)
    out = filename + ".hmac"
    with open(out, "wb") as f:
        f.write(der)
    print("[+] Writing HMAC DigestInfo to", out)

def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename + ".hmac")
    der = open(filename + ".hmac", "rb").read()
    val, rest = decoder.decode(der)
    algseq = val.getComponentByPosition(0)
    oid = algseq.getComponentByPosition(0)
    digest = bytes(val.getComponentByPosition(1))
    oid_str = ".".join(map(str, oid.asTuple()))
    algo = OID_TO_HASH.get(oid_str)
    print("[+] Digest from file:", digest.hex())
    print("[+] Algorithm OID:", oid_str, f"({algo.upper()})")
    key = input("[?] Enter key: ").encode()
    digest_calculated = hmac_file(filename, key, algo)
    print(f"[+] Calculated HMAC-{algo.upper()}:", digest_calculated.hex())
    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")

def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()

