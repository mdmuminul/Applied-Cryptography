#!/usr/bin/env python3

import argparse, codecs, hmac, socket, sys, time, os, datetime
from hashlib import sha1, sha256
from Cryptodome.Cipher import ARC4
from pyasn1.codec.der import decoder  # do not use any other imports/libraries
from urllib.parse import urlparse

# took 3.5 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def get_pubkey_certificate(cert):
    # reads the certificate and returns (n, e)
    s, _ = decoder.decode(cert)
    tbs = s[0]
    spki = tbs[6]
    pub_bits = spki[1]
    pub_bytes = pub_bits.asOctets()
    if len(pub_bytes) and pub_bytes[0] == 0x00:
        pub_bytes = pub_bytes[1:]
    rsapk, _ = decoder.decode(pub_bytes)
    n = int(rsapk[0])
    e = int(rsapk[1])
    return n, e

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    k = (n.bit_length() + 7) // 8
    ps_len = k - len(plaintext) - 3
    ps = b""
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b
    return b"\x00\x02" + ps + b"\x00" + plaintext

def rsa_encrypt(cert, m):
    # encrypts message m using public key from certificate cert
    n, e = get_pubkey_certificate(cert)
    em = pkcsv15pad_encrypt(m, n)
    c = pow(bi(em), e, n)
    return ib(c, (n.bit_length() + 7) // 8)

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length == False:
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

# returns TLS record that contains ClientHello handshake message
def client_hello():
    global client_random, handshake_messages

    print("--> ClientHello()")

    version = b"\x03\x03"
    timestamp = int(time.time())
    client_random = ib(timestamp, 4) + os.urandom(28)

    session_id = b""
    session_id_len = b"\x00"

    cipher_suites = b"\x00\x05"  # TLS_RSA_WITH_RC4_128_SHA
    cipher_suites_len = ib(len(cipher_suites), 2)

    compression_methods = b"\x01\x00"  # length=1, null

    body = (
        version +
        client_random +
        session_id_len + session_id +
        cipher_suites_len + cipher_suites +
        compression_methods
    )

    htype = b"\x01"
    hlength = ib(len(body), 3)
    handshake = htype + hlength + body
    handshake_messages += handshake

    record_header = b"\x16" + version + ib(len(handshake), 2)
    record = record_header + handshake

    return record

# returns TLS record that contains ClientKeyExchange message containing encrypted pre-master secret
def client_key_exchange():
    global server_cert, premaster, handshake_messages

    print("--> ClientKeyExchange()")

    premaster = b"\x03\x03" + os.urandom(46)
    enc_pms = rsa_encrypt(server_cert, premaster)

    body = ib(len(enc_pms), 2) + enc_pms
    htype = b"\x10"
    hlength = ib(len(body), 3)
    handshake = htype + hlength + body
    handshake_messages += handshake

    record = b"\x16\x03\x03" + ib(len(handshake), 2) + handshake

    return record

# returns TLS record that contains ChangeCipherSpec message
def change_cipher_spec():
    print("--> ChangeCipherSpec()")
    record = b"\x14\x03\x03" + ib(1, 2) + b"\x01"
    return record

# returns TLS record that contains encrypted Finished handshake message
def finished():
    global handshake_messages, master_secret

    print("--> Finished()")
    client_verify = PRF(
        master_secret,
        b"client finished" + sha256(handshake_messages).digest(),
        12
    )

    body = client_verify
    htype = b"\x14"
    hlength = ib(len(body), 3)
    handshake = htype + hlength + body
    handshake_messages += handshake

    ciphertext = encrypt(handshake, b"\x16", b"\x03\x03")
    record = b"\x16\x03\x03" + ib(len(ciphertext), 2) + ciphertext

    return record

# returns TLS record that contains encrypted Application data
def application_data(data):
    print("--> Application_data()")
    print(data.decode().strip())

    ciphertext = encrypt(data, b"\x17", b"\x03\x03")
    record = b"\x17\x03\x03" + ib(len(ciphertext), 2) + ciphertext

    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received, server_random, server_cert
    global handshake_messages, server_change_cipher_spec_received
    global server_finished_received, server_verify

    # decrypt if encryption enabled
    if server_change_cipher_spec_received:
        r = decrypt(r, b"\x16", b"\x03\x03")

    # read Handshake message type and length from message header
    htype, hlength = r[0:1], bi(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages += handshake

    if htype == b"\x02":
        print("	<--- ServerHello()")
        version = body[0:2]
        server_random = body[2:34]
        print("[+] server randomness:", server_random.hex().upper())
        ts = bi(server_random[0:4])
        print("[+] server timestamp:",
              datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
        sid_len = body[34]
        offset = 35
        session_id = body[offset:offset+sid_len]
        print("[+] TLS session ID:", session_id.hex().upper())
        offset += sid_len
        cipher_suite = body[offset:offset+2]
        if cipher_suite == b"\x00\x05":
            cs_name = "TLS_RSA_WITH_RC4_128_SHA"
        else:
            cs_name = cipher_suite.hex()
        print("[+] Cipher suite:", cs_name)

    elif htype == b"\x0b":
        print("	<--- Certificate()")
        total_len = bi(body[0:3])
        offset = 3
        cert_len = bi(body[offset:offset+3])
        server_cert = body[offset+3:offset+3+cert_len]
        print("[+] Server certificate length:", len(server_cert))

        if args.certificate:
            pem = (
                b"-----BEGIN CERTIFICATE-----\n" +
                codecs.encode(server_cert, 'base64') +
                b"-----END CERTIFICATE-----\n"
            )
            with open(args.certificate, "wb") as f:
                f.write(pem)

    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        server_hello_done_received = True

    elif htype == b"\x14":
        print("	<--- Finished()")
        server_verify = body
        verify_data_calc = PRF(
            master_secret,
            b"server finished" + sha256(handshake_messages[:-4-hlength]).digest(),
            12
        )
        if server_verify != verify_data_calc:
            print("[-] Server finished verification failed!")
            sys.exit(1)
        server_finished_received = True

    else:
        print("[-] Unknown Handshake Type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received

    # parse TLS record header and pass the record body to the corresponding parsing method
    ctype = r[0:1]
    c = r[5:]

    # handle known types
    if ctype == b"\x16":
        print("<--- Handshake()")
        parsehandshake(c)
    elif ctype == b"\x14":
        print("<--- ChangeCipherSpec()")
        server_change_cipher_spec_received = True
    elif ctype == b"\x15":
        print("<--- Alert()")
        level, desc = c[0], c[1]
        if level == 1:
            print("	[-] warning:", desc)
        elif level == 2:
            print("	[-] fatal:", desc)
            sys.exit(1)
        else:
            sys.exit(1)
    elif ctype == b"\x17":
        print("<--- Application_data()")
        data = decrypt(c, b"\x17", b"\x03\x03")
        print(data.decode().strip())
    else:
        print("[-] Unknown TLS Record type:", ctype.hex())
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):

    out = b""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random
    master_secret = PRF(
        premaster,
        b"master secret" + client_random + server_random,
        48
    )

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(
        master_secret,
        b"key expansion" + server_random + client_random,
        136
    )
    mac_size = 20
    key_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    mac = HMAC_sha1(
        client_mac_key,
        ib(client_seq, 8) + type + version + ib(len(plain), 2) + plain
    )
    ciphertext = rc4c.encrypt(plain + mac)
    client_seq += 1
    return ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s

    d = rc4s.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(
        server_mac_key,
        ib(server_seq, 8) + type + version + ib(len(plain), 2) + plain
    )
    if mac != mac_calc:
        print("[-] MAC verification failed!")
        sys.exit(1)
    server_seq += 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = b""

    # read TLS record header (5 bytes)
    for _ in range(5):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    # find data length
    datalen = bi(record[3:5])

    # read TLS record body
    for _ in range(datalen):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]

path = url.path

client_random = b""	# will hold client randomness
server_random = b""	# will hold server randomness
server_cert = b""	# will hold DER encoded server certificate
premaster = b""		# will hold 48 byte pre-master secret
master_secret = b""	# will hold master secret
handshake_messages = b"" # will hold concatenation of handshake messages

# client/server keys and sequence numbers
client_mac_key = b""
server_mac_key = b""
client_enc_key = b""
server_enc_key = b""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = b""
rc4s = b""

server_verify = b""

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()
s.send(finished())

while not server_finished_received:
    parserecord(readrecord())

s.send(application_data(b"GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print("[+] Closing TCP connection!")
s.close()

