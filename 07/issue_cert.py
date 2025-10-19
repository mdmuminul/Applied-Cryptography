#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took x.y hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

def ib(i, length=False):
    # converts integer to bytes
    if length is False:
        if i == 0:
            return b'\x00'
        length = (i.bit_length()+7)//8
    b = b''
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

def der_len(n):
    if n < 128:
        return bytes([n])
    s = ib(n)
    return bytes([0x80 | len(s)]) + s

def der_tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content

def der_INTEGER(n):
    b = ib(n)
    if b[0] & 0x80:
        b = b'\x00' + b  # ensure positive INTEGER
    return der_tlv(0x02, b)

def der_BIT_STRING(b, unused_bits=0):
    return der_tlv(0x03, bytes([unused_bits]) + b)

def der_OCTET_STRING(b):
    return der_tlv(0x04, b)

def der_NULL():
    return der_tlv(0x05, b'')

def der_OID(s):
    parts = [int(x) for x in s.split('.')]
    first = 40*parts[0] + parts[1]
    body = bytes([first])
    for p in parts[2:]:
        chunk = []
        if p == 0:
            chunk = [0]
        else:
            while p > 0:
                chunk.append(p & 0x7f)
                p >>= 7
            chunk.reverse()
        for i, v in enumerate(chunk):
            body += bytes([0x80 | v]) if i < len(chunk)-1 else bytes([v])
    return der_tlv(0x06, body)

def der_PrintableString(s):
    return der_tlv(0x13, s.encode('ascii'))

def der_UTF8String(s):
    return der_tlv(0x0C, s.encode('utf-8'))

def der_IA5String(s):
    return der_tlv(0x16, s.encode('ascii'))

def der_UTCTime(zbytes):
    return der_tlv(0x17, zbytes)

def der_Sequence(*items):
    return der_tlv(0x30, b''.join(items))

def der_Set(*items):
    # DER SET OF should be sorted; here we only place one element
    return der_tlv(0x31, b''.join(items))

def der_explicit(tagnum, inner):
    # context-specific EXPLICIT (constructed)
    return der_tlv(0xA0 | (tagnum & 0x1F), inner)

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = content.replace(b"-----BEGIN RSA PRIVATE KEY-----", b"")
        content = content.replace(b"-----END RSA PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads RSA private key file and returns (n, d)
    der = pem_to_der(open(filename, 'rb').read())
    obj = decoder.decode(der)[0]
    # Try PKCS#8 → privateKey OCTET STRING
    try:
        inner = bytes(obj[2])
        rsapriv = decoder.decode(inner)[0]
    except Exception:
        # Fall back to PKCS#1 RSAPrivateKey directly
        rsapriv = obj
    # RSAPrivateKey ::= SEQUENCE { version, n, e, d, ... }
    return int(rsapriv[1]), int(rsapriv[3])

def pkcsv15pad_sign(plaintext, n):
    # pads plaintext for signing according to PKCS#1 v1.5

    # calculate byte size of modulus n
    k = (n.bit_length()+7)//8

    # plaintext must be at least 11 bytes smaller than modulus
    if k < len(plaintext) + 11:
        raise ValueError("message too long for PKCS#1 v1.5")

    # add padding bytes
    ps = b'\xff' * (k - len(plaintext) - 3)
    return b'\x00\x01' + ps + b'\x00' + plaintext

OID_sha256            = "2.16.840.1.101.3.4.2.1"
OID_sha256WithRSA     = "1.2.840.113549.1.1.11"
OID_rsaEncryption     = "1.2.840.113549.1.1.1"
OID_commonName        = "2.5.4.3"
OID_basicConstraints  = "2.5.29.19"
OID_keyUsage          = "2.5.29.15"
OID_extendedKeyUsage  = "2.5.29.37"
OID_serverAuth        = "1.3.6.1.5.5.7.3.1"

def digestinfo_der(m):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m
    h = hashlib.sha256(m).digest()
    alg = der_Sequence(der_OID(OID_sha256), der_NULL())
    der_di = der_Sequence(alg, der_OCTET_STRING(h))
    return der_di

def sign(m, keyfile):
    # signs DigestInfo of message m
    n, d = get_privkey(keyfile)
    di = digestinfo_der(m)
    em = pkcsv15pad_sign(di, n)
    signature_int = pow(bi(em), d, n)
    signature = ib(signature_int, (n.bit_length()+7)//8)
    return signature

def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field

    # looping over Distinguished Name entries until CN found
    csr = decoder.decode(csr_der)[0]   # CertificationRequest
    name = csr[0][1]                   # subject (Name)
    for rdn in name:                   # RDNSequence
        for atv in rdn:                # AttributeTypeAndValue
            if str(atv[0]) == OID_commonName:
                v = atv[1]
                try:
                    return str(v)
                except Exception:
                    return bytes(v).decode('utf-8', 'ignore')
    raise ValueError("CN not found in CSR")

def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    csr = decoder.decode(csr_der)[0]
    spki = csr[0][2]
    return encoder.encode(spki)

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    cert = decoder.decode(cert_der)[0]   # Certificate
    # issuer = subject of CA certificate
    return encoder.encode(cert[0][5])    # tbsCertificate.subject

def alg_sha256WithRSA():
    return der_Sequence(der_OID(OID_sha256WithRSA), der_NULL())

def name_CN_only(cn_text):
    atv = der_Sequence(der_OID(OID_commonName), der_UTF8String(cn_text))
    rdn = der_Set(atv)
    return der_Sequence(rdn)

def validity_now_to_plus_100d_utc():
    import time
    now = int(time.time())
    nb = time.gmtime(now - 300)          # now - 5 minutes
    na = time.gmtime(now + 100*24*3600)  # +100 days (>= 3 months)
    def fmt(t):
        yy = t.tm_year % 100
        return f"{yy:02d}{t.tm_mon:02d}{t.tm_mday:02d}{t.tm_hour:02d}{t.tm_min:02d}{t.tm_sec:02d}Z".encode('ascii')
    return der_Sequence(der_UTCTime(fmt(nb)), der_UTCTime(fmt(na)))

def extensions_block():
    # Certificate extensions (critical:TRUE):
    #  - basic constraints CA:FALSE
    #  - key usage: digitalSignature
    #  - extended key usage: id-kp-serverAuth

    # basicConstraints: critical TRUE, CA:FALSE
    bc_val = der_Sequence(der_tlv(0x01, b'\x00'))  # BOOLEAN FALSE
    bc = der_Sequence(
        der_OID(OID_basicConstraints),
        der_tlv(0x01, b'\xff'),           # critical TRUE
        der_OCTET_STRING(bc_val)
    )

    # keyUsage: BIT STRING (MSB-first). bit0=digitalSignature=0x80
    ku_byte = bytes([0x80])               # ONLY digitalSignature
    ku_val = der_BIT_STRING(ku_byte, 0)
    ku = der_Sequence(
        der_OID(OID_keyUsage),
        der_tlv(0x01, b'\xff'),           # critical TRUE
        der_OCTET_STRING(ku_val)
    )

    # extendedKeyUsage: critical TRUE, serverAuth
    eku_val = der_Sequence(der_OID(OID_serverAuth))
    eku = der_Sequence(
        der_OID(OID_extendedKeyUsage),
        der_tlv(0x01, b'\xff'),           # critical TRUE
        der_OCTET_STRING(eku_val)
    )

    # [3] EXPLICIT SEQUENCE OF Extension
    return der_explicit(3, der_Sequence(bc, ku, eku))

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format
    import random
    serial = (random.getrandbits(64) | 1)  # any positive non-zero serial
    tbs = der_Sequence(
        der_explicit(0, der_INTEGER(2)),   # version v3
        der_INTEGER(serial),
        alg_sha256WithRSA(),               # signature (algorithm identifier)
        issuer,
        validity_now_to_plus_100d_utc(),
        subject,
        pubkey,
        extensions_block()
    )
    signature = sign(tbs, private_key_file)
    cert = der_Sequence(
        tbs,
        alg_sha256WithRSA(),
        der_BIT_STRING(signature, 0)
    )
    pem = (b"-----BEGIN CERTIFICATE-----\n" +
           codecs.encode(cert, 'base64') +
           b"-----END CERTIFICATE-----\n")
    return pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
# subject = asn1_sequence(...)
subject = name_CN_only(subject_cn_text)  # CN only, per task

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)

