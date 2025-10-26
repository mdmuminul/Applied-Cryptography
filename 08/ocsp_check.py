#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

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

#==== ASN1 encoder end ====


def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    cert_asn1, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())
    tbs = cert_asn1.getComponentByName('tbsCertificate')
    subject = tbs.getComponentByName('subject')
    name = encoder.encode(subject)
    return name

def get_key(cert):
     # gets subjectPublicKey from certificate
    cert_asn1, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())
    tbs = cert_asn1.getComponentByName('tbsCertificate')
    spki = tbs.getComponentByName('subjectPublicKeyInfo')
    spk_bits = spki.getComponentByName('subjectPublicKey')
    subjectPublicKey = bytes(spk_bits.asOctets())
    return subjectPublicKey

def get_serial(cert):
    # gets serial from certificate
    cert_asn1, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())
    tbs = cert_asn1.getComponentByName('tbsCertificate')
    serial = tbs.getComponentByName('serialNumber')
    return int(serial)

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    issuerNameHash = hashlib.sha1(issuer_name).digest()
    issuerKeyHash = hashlib.sha1(issuer_key).digest()

    alg = rfc5280.AlgorithmIdentifier()
    alg.setComponentByName('algorithm', univ.ObjectIdentifier('1.3.14.3.2.26'))
    alg.setComponentByName('parameters', univ.Null())

    certid = rfc2560.CertID()
    certid.setComponentByName('hashAlgorithm', alg)
    certid.setComponentByName('issuerNameHash', univ.OctetString(issuerNameHash))
    certid.setComponentByName('issuerKeyHash', univ.OctetString(issuerKeyHash))
    certid.setComponentByName('serialNumber', univ.Integer(serial))

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    req = rfc2560.Request()
    req.setComponentByName('reqCert', certid)

    class RequestList(univ.SequenceOf):
        componentType = rfc2560.Request()
    rl = RequestList()
    rl.setComponentByPosition(0, req)

    tbs_req = rfc2560.TBSRequest()
    tbs_req.setComponentByName('requestList', rl)

    ocsp_req = rfc2560.OCSPRequest()
    ocsp_req.setComponentByName('tbsRequest', tbs_req)

    request = encoder.encode(ocsp_req)

    return request

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    # parse OCSP responder's url
    parsed = urlparse(ocsp_url)
    host = parsed.netloc
    path = parsed.path
    if path == '':
        path = '/'

    print("[+] Connecting to %s..." % (host))
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    # send HTTP POST request
    body = ocsp_req
    hdr = (
        "POST " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Content-Type: application/ocsp-request\r\n" +
        "Content-Length: " + str(len(body)) + "\r\n" +
        "Connection: close\r\n" +
        "\r\n"
    ).encode()
    s.sendall(hdr + body)

    # read HTTP response header
    header_bytes = b''
    while b"\r\n\r\n" not in header_bytes:
        chunk = s.recv(1)
        if len(chunk) == 0:
            break
        header_bytes += chunk

    # get HTTP response length
    m = re.search(b'content-length:\\s*(\\d+)\\s', header_bytes, re.I|re.S)
    if not m:
        content_len = 0
    else:
        content_len = int(m.group(1))

    # read HTTP response body
    ocsp_resp = b''
    while len(ocsp_resp) < content_len:
        chunk = s.recv(1)
        if len(chunk) == 0:
            break
        ocsp_resp += chunk

    s.close()

    return ocsp_resp

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    cert_asn1, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())
    tbs = cert_asn1.getComponentByName('tbsCertificate')
    exts = tbs.getComponentByName('extensions')
    for seq in exts:
        if str(seq.getComponentByName('extnID'))=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq.getComponentByName('extnValue'))
            aia_list, _ = decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())
            for aia in aia_list:
                if str(aia.getComponentByName('accessMethod'))=='1.3.6.1.5.5.7.48.1': # ocsp url
                    gn = aia.getComponentByName('accessLocation')
                    return str(gn.getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    sys.exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())

    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    cert_asn1, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())
    tbs = cert_asn1.getComponentByName('tbsCertificate')
    exts = tbs.getComponentByName('extensions')
    for seq in exts:
        if str(seq.getComponentByName('extnID'))=='1.3.6.1.5.5.7.1.1':
            ext_value = bytes(seq.getComponentByName('extnValue'))
            aia_list, _ = decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())
            for aia in aia_list:
                if str(aia.getComponentByName('accessMethod'))=='1.3.6.1.5.5.7.48.2': # caIssuers
                    gn = aia.getComponentByName('accessLocation')
                    return str(gn.getComponentByName('uniformResourceIdentifier'))

    print("[-] Issuer cert url not found in the certificate!")
    sys.exit(1)

def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)
    host = url.netloc
    path = url.path
    if path == '':
        path = '/'

    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    # send HTTP GET request
    req = (
        "GET " + path + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Connection: close\r\n" +
        "\r\n"
    ).encode()
    s.sendall(req)

    # read HTTP response header
    header_bytes = b''
    while b"\r\n\r\n" not in header_bytes:
        chunk = s.recv(1)
        if len(chunk) == 0:
            break
        header_bytes += chunk

    # get HTTP response length
    m = re.search(b'content-length:\\s*(\\d+)\\s', header_bytes, re.I|re.S)
    if not m:
        content_len = 0
    else:
        content_len = int(m.group(1))

    # read HTTP response body
    issuer_cert = b''
    while len(issuer_cert) < content_len:
        chunk = s.recv(1)
        if len(chunk) == 0:
            break
        issuer_cert += chunk

    s.close()

    return issuer_cert

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)


# main
cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert_raw = download_issuer_cert(issuer_cert_url)

# issuer cert may be DER or PEM
try:
    decoder.decode(issuer_cert_raw, asn1Spec=rfc5280.Certificate())
    issuer_cert_der = issuer_cert_raw
except Exception:
    issuer_cert_der = pem_to_der(issuer_cert_raw)

ocsp_req = produce_request(cert, issuer_cert_der)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)

