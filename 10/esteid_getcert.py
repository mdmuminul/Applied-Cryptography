#!/usr/bin/env python3

import argparse, codecs, sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString
from smartcard.System import readers

# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='Fetch certificates from ID card', add_help=False)
parser.add_argument('--cert', type=str, default=None, choices=['auth','sign'], help='Which certificate to fetch')
parser.add_argument("--out", required=True, type=str, help="File to store certificate (PEM)")
args = parser.parse_args()

if args.cert is None:
    print("[-] Please specify --cert auth|sign")
    sys.exit(1)

# robust connector (prevents "Context already released")
def connect_channel():
    rl = readers()
    for r in rl:
        try:
            ch = r.createConnection(); ch.connect(CardConnection.T0_protocol); return ch
        except:
            pass
        try:
            ch = r.createConnection(); ch.connect(CardConnection.T1_protocol); return ch
        except:
            pass
        try:
            ch = r.createConnection(); ch.connect(); return ch
        except:
            pass
    # fallback: wait for a card and retry a couple of times
    for _ in range(2):
        ch = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
        try:
            ch.connect(CardConnection.T0_protocol); return ch
        except:
            try:
                ch = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
                ch.connect(CardConnection.T1_protocol); return ch
            except:
                ch = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
                ch.connect(); return ch

channel = connect_channel()
print("[+] Selected reader:", channel.getReader())

# detect and print the EstEID card platform (lenient ATR matching)
atr = channel.getATR()
def atr_starts(prefix):
    return len(atr) >= len(prefix) and atr[:len(prefix)] == prefix

is_2018 = False
is_legacy = False

if atr_starts([0x3B,0xFA,0x18]):  # v3.5 cold (eID)
    print("[+] EstEID v3.5 (10.2014) cold (eID)"); is_legacy = True
elif atr_starts([0x3B,0xFE,0x18]):  # v3.x JavaCard
    print("[+] EstEID v3.x on JavaCard"); is_legacy = True
elif len(atr) >= 2 and atr[0] == 0x3B and atr[1] in (0xDB, 0xDE, 0xDC):  # 2018 variants
    print("[+] Estonian ID card (2018)"); is_2018 = True
else:
    print("[-] Unknown card:", toHexString(atr)); sys.exit(1)

def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)
    if [sw1,sw2] == [0x90,0x00]:
        return data
    elif sw1 == 0x61:
        return send([0x00, 0xC0, 0x00, 0x00, sw2])  # GET RESPONSE
    elif sw1 == 0x6C:
        return send(apdu[0:4] + [sw2])              # resend with corrected Le
    else:
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu))); sys.exit(1)

def select_2018_aid():
    """Try 20-byte AID first (per slides), fall back to 16-byte AID."""
    # 20-byte AID: A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00 20 18
    try:
        send([0x00,0xA4,0x04,0x00,0x14,
              0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,
              0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00,0x20,0x18])
        return
    except SystemExit:
        raise
    except:
        pass
    # 16-byte AID (older docs): A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00
    send([0x00,0xA4,0x04,0x00,0x10,
          0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,
          0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00])

def select_cert_file(cert_kind):
    """
    cert_kind: 'auth' or 'sign'
    Point at the EF containing the DER cert.
    """
    if is_2018:
        select_2018_aid()
        send([0x00,0xA4,0x00,0x0C])  # MF
        if cert_kind == 'auth':
            # MF/ADF1/3401  (EF id is 0x3401 → 2 bytes!)
            send([0x00,0xA4,0x01,0x0C,0x02,0xAD,0xF1])       # ADF1
            send([0x00,0xA4,0x02,0x0C,0x02,0x34,0x01])       # EF 3401
        else:
            # MF/ADF2/341F  (EF id is 0x341F → 2 bytes!)
            send([0x00,0xA4,0x01,0x0C,0x02,0xAD,0xF2])       # ADF2
            send([0x00,0xA4,0x02,0x0C,0x02,0x34,0x1F])       # EF 341F
    else:
        # Legacy: MF/EEEE/(AACE or DDCE)
        send([0x00,0xA4,0x00,0x0C])                     # MF
        send([0x00,0xA4,0x01,0x0C,0x02,0xEE,0xEE])      # DF EEEE
        if cert_kind == 'auth':
            send([0x00,0xA4,0x02,0x0C,0x02,0xAA,0xCE])  # EF AACE
        else:
            send([0x00,0xA4,0x02,0x0C,0x02,0xDD,0xCE])  # EF DDCE

def fetch_bytes(offset, n):
    out = bytearray()
    done = 0
    while done < n:
        chunk_len = n - done
        if chunk_len > 231: chunk_len = 231
        off = offset + done
        p1, p2 = (off >> 8) & 0xFF, off & 0xFF
        chunk = send([0x00,0xB0,p1,p2,chunk_len])
        if not chunk:
            print("[-] Zero-length READ BINARY"); sys.exit(1)
        out.extend(chunk)
        done += len(chunk)
    return bytes(out)

def parse_der_total_len(first_bytes):
    if len(first_bytes) < 2 or first_bytes[0] != 0x30:
        print("[-] Unexpected certificate header"); sys.exit(1)
    l0 = first_bytes[1]
    if l0 < 0x80:
        return 1 + 1 + l0
    nbytes = l0 & 0x7F
    if nbytes < 1 or nbytes > 4:
        print("[-] Unsupported/too-long DER length form"); sys.exit(1)
    need = 2 + nbytes
    if len(first_bytes) < need:
        print("[-] Not enough bytes to parse DER length"); sys.exit(1)
    value_len = 0
    for i in range(nbytes):
        value_len = (value_len << 8) | first_bytes[2+i]
    return 1 + 1 + nbytes + value_len

print("[=] Retrieving %s certificate..." % (args.cert))

# 1) Select EF
select_cert_file(args.cert)

# 2) Read header to determine DER length (start with 10 bytes; fetch more only if needed)
header = fetch_bytes(0, 10)
if header[0] != 0x30:
    print("[-] Certificate does not start with SEQUENCE (0x30)"); sys.exit(1)

l0 = header[1]
if l0 < 0x80:
    certlen = 1 + 1 + l0
else:
    nbytes = l0 & 0x7F
    need = 2 + nbytes
    if need > len(header):
        header = header + fetch_bytes(len(header), need - len(header))
    certlen = parse_der_total_len(header[:need])

print("[+] Certificate size: %d bytes" % (certlen))

# 3) Read exactly certlen bytes in 231-byte chunks
data = bytearray()
offset = 0
while offset < certlen:
    n = certlen - offset
    if n > 231: n = 231
    p1, p2 = (offset >> 8) & 0xFF, offset & 0xFF
    chunk = send([0x00,0xB0,p1,p2,n])
    if not chunk:
        print("[-] Zero-length READ BINARY"); sys.exit(1)
    data.extend(chunk)
    offset += len(chunk)

cert = bytes(data[:certlen])

# 4) Save PEM
open(args.out,"wb").write(
    b"-----BEGIN CERTIFICATE-----\n" +
    codecs.encode(cert, 'base64') +
    b"-----END CERTIFICATE-----\n"
)
print("[+] Certificate stored in", args.out)

