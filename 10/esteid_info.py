#!/usr/bin/env python3

import sys     # do not use any other imports/libraries
from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString

# took x.y hours (please specify here how much time your solution required)


# this will wait until a card is inserted in any reader
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

# detect and print the EstEID card platform
atr = channel.getATR()
is_esteid_2018 = False

def atr_starts(prefix):
    return len(atr) >= len(prefix) and atr[:len(prefix)] == prefix

if atr_starts([0x3B,0xFA,0x18]):
    print("[+] EstEID v3.5 (10.2014) cold (eID)")
elif atr_starts([0x3B,0xFE,0x18]):
    print("[+] EstEID v3.x on JavaCard")
elif len(atr) >= 2 and atr[0] == 0x3B and atr[1] in (0xDB, 0xDE, 0xDC):
    print("[+] Estonian ID card (2018)")
    is_esteid_2018 = True
else:
    print("[-] Unknown card:", toHexString(atr))
    sys.exit(1)

# wrapper
def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)
    if [sw1,sw2] == [0x90,0x00]:
        return data
    elif sw1 == 0x61:
        return send([0x00, 0xC0, 0x00, 0x00, sw2])
    elif sw1 == 0x6C:
        return send(apdu[0:4] + [sw2])
    else:
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu)))
        sys.exit(1)


# reading personal data file (EstEID spec page 23)


table = {
1:'Surname',
2:'First name line 1',
3:'First name line 2',
4:'Sex',
5:'Nationality',
6:'Birth date',
7:'Personal ID code',
8:'Document number',
9:'Expiry date',
10:'Place of birth',
11:'Date of issuance',
12:'Type of residence permit',
13:'Notes line 1',
14:'Notes line 2',
15:'Notes line 3',
16:'Notes line 4',
}

table_2018 = {
1:'Surname',
2:'First name',
3:'Sex',
4:'Citizenship',
5:'Date & place of birth',
6:'Personal ID code',
7:'Document number',
8:'Expiry date',
9:'Date & place of issuance',
10:'Type of residence permit',
11:'Notes line 1',
12:'Notes line 2',
13:'Notes line 3',
14:'Notes line 4',
15:'Notes line 5',
}

# print all enteries from the personal data file
print("[+] Personal data file:\n")
if is_esteid_2018:
    send([0x00,0xA4,0x04,0x00,0x10,0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00])
    send([0x00,0xA4,0x00,0x0C])
    send([0x00,0xA4,0x01,0x0C,0x02,0x50,0x00])
    for i in range(1,16):
        send([0x00,0xA4,0x02,0x0C,0x02,0x50,i])
        r = bytes(send([0x00,0xB0,0x00,0x00,0x00]))
        try:
            s = r.decode("utf8").rstrip("\x00").strip()
        except:
            s = ""
        print("[{}]{}: {}".format(i, table_2018[i], s))
else:
    send([0x00,0xA4,0x00,0x0C])
    send([0x00,0xA4,0x01,0x0C,0x02,0xEE,0xEE])
    send([0x00,0xA4,0x02,0x0C,0x02,0x50,0x44])
    for i in range(1,17):
        r = bytes(send([0x00,0xB2,i,0x04]))
        try:
            s = r.decode("cp1252").rstrip("\x00").strip()
        except:
            s = ""
        print("[{}]{}: {}".format(i, table[i], s))
print("")

# reading PIN retry counters from the card
print("[+] PIN retry counters:")
if is_esteid_2018:
    def tries(p2, default_val=3):
        d, sw1, sw2 = channel.transmit([0x00,0x20,0x00,p2])
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            return (sw2 & 0x0F)
        if [sw1,sw2] == [0x90,0x00]:
            return default_val
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString([0x00,0x20,0x00,p2])))
        sys.exit(1)
    pin1 = tries(0x01)
    pin2 = tries(0x85)
    puk  = tries(0x02)
else:
    send([0x00,0xA4,0x00,0x0C])
    send([0x00,0xA4,0x01,0x0C,0x02,0x00,0x16])
    def rr(n):
        r = send([0x00,0xB2,n,0x04])
        return r[5] if len(r) >= 6 else 0
    pin1 = rr(1)
    pin2 = rr(2)
    puk  = rr(3)

print("PIN1: {} left".format(pin1))
print("PIN2: {} left".format(pin2))
print("PUK: {} left".format(puk))

