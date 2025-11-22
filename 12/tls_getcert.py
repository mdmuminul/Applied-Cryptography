#!/usr/bin/env python3

import argparse, codecs, datetime, os, socket, sys, time  # do not use any other imports/libraries
from urllib.parse import urlparse

# took 2.0 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length == False:
        length = (i.bit_length() + 7) // 8
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

# returns TLS record that contains ClientHello Handshake message
def client_hello():
    global host

    print("--> ClientHello()")

    # list of cipher suites the client supports
    csuite  = b"\xC0\x2F"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    csuite += b"\xC0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    csuite += b"\xC0\x2B"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    csuite += b"\xC0\x2C"  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    csuite += b"\x00\x05"  # TLS_RSA_WITH_RC4_128_SHA
    csuite += b"\x00\x2F"  # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA

    version = b"\x03\x03"  # TLS 1.2

    gmt_unix_time = int(time.time())
    rnd = ib(gmt_unix_time, 4) + os.urandom(28)  # 32 bytes, first 4 = timestamp

    session_id = b""
    session_id_len = b"\x00"

    cipher_suites_len = ib(len(csuite), 2)
    compression_methods = b"\x01\x00"  # length 1, method 0 (null)

    # --- extensions ---

    # SNI (server_name) extension (type 0x0000)
    host_bytes = host.encode("ascii")
    server_name = b"\x00" + ib(len(host_bytes), 2) + host_bytes
    server_name_list = ib(len(server_name), 2) + server_name
    ext_sni_data = server_name_list
    ext_sni = b"\x00\x00" + ib(len(ext_sni_data), 2) + ext_sni_data

    # signature_algorithms extension (type 0x000d)
    # list: rsa/sha256, rsa/sha384, rsa/sha512, rsa/sha1, ecdsa/sha256, ecdsa/sha384, ecdsa/sha512, ecdsa/sha1
    sig_list  = b"\x04\x01"  # rsa_pkcs1_sha256
    sig_list += b"\x05\x01"  # rsa_pkcs1_sha384
    sig_list += b"\x06\x01"  # rsa_pkcs1_sha512
    sig_list += b"\x02\x01"  # rsa_pkcs1_sha1
    sig_list += b"\x04\x03"  # ecdsa_secp256r1_sha256
    sig_list += b"\x05\x03"  # ecdsa_secp384r1_sha384
    sig_list += b"\x06\x03"  # ecdsa_secp521r1_sha512
    sig_list += b"\x02\x03"  # ecdsa_sha1
    ext_sig_data = ib(len(sig_list), 2) + sig_list
    ext_sig = b"\x00\x0d" + ib(len(ext_sig_data), 2) + ext_sig_data

    # supported_groups (elliptic curves) extension (type 0x000a)
    # secp256r1 (0x0017), secp384r1 (0x0018), secp521r1 (0x0019)
    groups = b"\x00\x17\x00\x18\x00\x19"
    ext_grp_data = ib(len(groups), 2) + groups
    ext_grp = b"\x00\x0a" + ib(len(ext_grp_data), 2) + ext_grp_data

    # ec_point_formats extension (type 0x000b) – only "uncompressed" (0)
    pt_formats = b"\x01\x00"  # length 1, value 0 (uncompressed)
    ext_ecpf = b"\x00\x0b" + ib(len(pt_formats), 2) + pt_formats

    extensions = ext_sni + ext_sig + ext_grp + ext_ecpf
    extensions_len = ib(len(extensions), 2)

    body = (
        version +
        rnd +
        session_id_len + session_id +
        cipher_suites_len + csuite +
        compression_methods +
        extensions_len + extensions
    )

    # add Handshake message header
    hlen = ib(len(body), 3)
    handshake = b"\x01" + hlen + body  # client_hello type = 1

    # add record layer header
    rlen = ib(len(handshake), 2)
    record = b"\x16" + b"\x03\x03" + rlen + handshake  # type 22 (handshake)

    return record

# returns TLS record that contains 'Certificate unknown' fatal Alert message
def alert():
    print("--> Alert()")

    alert_msg = b"\x02\x2e"  # level=fatal(2), description=certificate_unknown(46)

    rlen = ib(len(alert_msg), 2)
    record = b"\x15" + b"\x03\x03" + rlen + alert_msg  # type 21 (alert)

    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received

    if len(r) < 4:
        return

    htype = r[0:1]
    hlen = bi(r[1:4])
    body = r[4:4+hlen]

    if htype == b"\x02":
        print("	<--- ServerHello()")

        idx = 0
        version = body[idx:idx+2]; idx += 2
        server_random = body[idx:idx+32]; idx += 32

        ts = bi(server_random[:4])
        gmt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        sessid_len = body[idx]; idx += 1
        sessid = body[idx:idx+sessid_len]; idx += sessid_len

        cipher = body[idx:idx+2]; idx += 2
        compression = body[idx:idx+1]; idx += 1

        print("	[+] server randomness:", server_random.hex().upper())
        print("	[+] server timestamp:", gmt)
        print("	[+] TLS session ID:", sessid.hex().upper())

        if cipher == b"\x00\x2f":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA")
        elif cipher == b"\x00\x35":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA")
        elif cipher == b"\x00\x05":
            print("	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA")
        elif cipher == b"\xC0\x2F":
            print("	[+] Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        elif cipher == b"\xC0\x30":
            print("	[+] Cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        elif cipher == b"\xC0\x2B":
            print("	[+] Cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        elif cipher == b"\xC0\x2C":
            print("	[+] Cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
        else:
            print("	[+] Cipher suite:", cipher.hex())

        if compression != b"\x00":
            print("[-] Wrong compression:", compression.hex())
            sys.exit(1)

    elif htype == b"\x0b":
        print("	<--- Certificate()")
        idx = 0
        cert_list_len = bi(body[idx:idx+3]); idx += 3
        if cert_list_len == 0:
            print("[-] Empty certificate list")
            sys.exit(1)
        certlen = bi(body[idx:idx+3]); idx += 3
        cert = body[idx:idx+certlen]

        print("	[+] Server certificate length:", certlen)
        if args.certificate:
            pem = "-----BEGIN CERTIFICATE-----\n" + \
                  codecs.encode(cert, "base64").decode("ascii") + \
                  "-----END CERTIFICATE-----\n"
            with open(args.certificate, "w") as f:
                f.write(pem)
            print("	[+] Server certificate saved in:", args.certificate)

    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        server_hello_done_received = True

    else:
        # ignore other handshake types
        pass

    # handle the case of several Handshake messages in one record
    leftover = r[4+hlen:]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    if len(r) < 5:
        return

    rectype = r[0:1]
    version = r[1:3]
    length = bi(r[3:5])
    body = r[5:5+length]

    if rectype == b"\x16":  # Handshake
        print("<--- Handshake()")
        parsehandshake(body)
    elif rectype == b"\x15":  # Alert
        print("<--- Alert()")
        if len(body) >= 2:
            level = body[0:1]
            description = body[1]
            if level == b"\x01":
                print("[-] warning:", description)
            elif level == b"\x02":
                print("[-] fatal:", description)
            else:
                print("[-] unknown alert level:", level.hex(), "desc:", description)
        else:
            print("[-] malformed alert")
        # after a fatal/warning from server, just stop
        return
    else:
        # ignore other record types for this task
        pass

# read from the socket full TLS record
def readrecord():
    global s

    record = b""

    # read the TLS record header (5 bytes)
    header = b""
    try:
        while len(header) < 5:
            chunk = s.recv(5 - len(header))
            if not chunk:
                break
            header += chunk
    except OSError:
        return b""

    if len(header) < 5:
        return b""

    # find data length
    length = bi(header[3:5])

    # read the TLS record body
    body = b""
    try:
        while len(body) < length:
            chunk = s.recv(length - len(body))
            if not chunk:
                break
            body += chunk
    except OSError:
        return b""

    record = header + body

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

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    rec = readrecord()
    if not rec:
        break
    parserecord(rec)

try:
    s.send(alert())
except OSError:
    pass

print("[+] Closing TCP connection!")
s.close()
