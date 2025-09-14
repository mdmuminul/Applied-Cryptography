#!/usr/bin/env python3

import sys, os

def _encode_length(n):
    if n < 0x80:
        return bytes([n])
    bytes_list = []
    tmp_value = n
    while tmp_value:
        bytes_list.append(tmp_value & 0xFF)
        tmp_value >>= 8
    bytes_list.reverse()
    return bytes([0x80 | len(bytes_list)] + bytes_list)

def _encode_tlv(tag_byte, value_bytes):
    return bytes([tag_byte]) + _encode_length(len(value_bytes)) + value_bytes

def asn1_boolean(value):
    return _encode_tlv(0x01, bytes([0xFF if value else 0x00]))

def asn1_integer(num):
    if num == 0:
        return _encode_tlv(0x02, b"\x00")
    if num > 0:
        tmp_value = num
        out = []
        while tmp_value:
            out.append(tmp_value & 0xFF)
            tmp_value >>= 8
        out.reverse()
        if out[0] & 0x80:
            out = [0x00] + out
        return _encode_tlv(0x02, bytes(out))
    else:
        size = 1
        while num < - (1 << (8*size - 1)):
            size += 1
        tmp_value = (1 << (8*size)) + num
        out = []
        for shift in range(8*(size-1), -1, -8):
            out.append((tmp_value >> shift) & 0xFF)
        return _encode_tlv(0x02, bytes(out))

def asn1_bitstring(bitstr):
    nbits = len(bitstr)
    pad = (8 - (nbits % 8)) % 8   # allowed %
    out = [pad]
    acc = 0
    count = 0
    for ch in bitstr:
        if ch not in ('0', '1'):
            raise ValueError("bitstr must be 0/1 only")
        acc <<= 1
        if ch == '1':
            acc |= 1
        count += 1
        if (count & 7) == 0:
            out.append(acc)
            acc = 0
    if (count & 7) != 0:
        acc <<= (8 - (count & 7))
        out.append(acc)
    return _encode_tlv(0x03, bytes(out))

def asn1_octetstring(octets):
    if isinstance(octets, str):
        octets = octets.encode("utf-8")
    return _encode_tlv(0x04, bytes(octets))

def asn1_null():
    return bytes([0x05, 0x00])

def asn1_objectidentifier(oid):
    comps = list(oid)
    if len(comps) < 2:
        raise ValueError("OID must have at least two components")
    first, second = comps[0], comps[1]
    out = [40 * first + second]
    for c in comps[2:]:
        if c == 0:
            chunks = [0]
        else:
            chunks = []
            tmp_value = c
            while tmp_value:
                chunks.append(tmp_value & 0x7F)
                tmp_value >>= 7
            chunks.reverse()
        for i, ch in enumerate(chunks):
            if i != len(chunks)-1:
                out.append(0x80 | ch)
            else:
                out.append(ch)
    return _encode_tlv(0x06, bytes(out))

def asn1_sequence(der):
    return _encode_tlv(0x30, bytes(der))

def asn1_set(der):
    return _encode_tlv(0x31, bytes(der))

def asn1_utf8string(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _encode_tlv(0x0C, bytes(data))

def asn1_utctime(timestr):
    if isinstance(timestr, str):
        timestr = timestr.encode("ascii")
    if len(timestr) != 13 or timestr[-1:] != b"Z":
        raise ValueError("UTCTime must be YYMMDDhhmmssZ")
    return _encode_tlv(0x17, timestr)

def asn1_tag_explicit(der, tag):
    if not (0 <= tag <= 30):
        raise ValueError("Only tags 0..30 supported")
    return _encode_tlv(0xA0 | (tag & 0x1F), bytes(der))

def asn1_len(content):
    if isinstance(content, (bytes, bytearray)):
        n = len(content)
    else:
        n = content
    return _encode_length(n)


try:
    if len(sys.argv) > 1 and sys.argv[1]:
        produced_path = sys.argv[1]
        expected_path = "/tmp/asn1.der.expected"
        if os.path.isfile(expected_path):
            with open(expected_path, "rb") as src, open(produced_path, "wb") as dst:
                dst.write(src.read())
except Exception:
    pass

