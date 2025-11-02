#!/usr/bin/env python3

# do not use any other imports/libraries
import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
from M2Crypto import X509, EC
import lxml.etree
from bs4 import BeautifulSoup
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560

# took x.y hours (please specify here how much time your solution required)

def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    x509 = X509.load_cert_der_string(cert)
    EC_pubkey = EC.pub_key_from_der(x509.get_pubkey().as_der())
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    return ts, ts_digestinfo

def parse_ocsp_response(ocsp_resp):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    certID = response0.getComponentByName('certID')
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    root = et.getroot()
    node = None
    for elem in root.iter():
        if lxml.etree.QName(elem.tag).localname == tagname:
            node = elem
            break
    if node is None:
        print(f"[-] canonicalize(): element <{tagname}> not found")
        exit(1)
    output = io.BytesIO()
    lxml.etree.ElementTree(node).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''

def b64(x):
    return codecs.encode(x, 'base64').replace(b'\n', b'')

def b64decode_text(text):
    return codecs.decode(text.encode('ascii'), 'base64')

def pick_hash(alg_uri):
    if alg_uri is None:
        return hashlib.sha256
    if alg_uri.endswith('sha256'):
        return hashlib.sha256
    if alg_uri.endswith('sha384'):
        return hashlib.sha384
    return hashlib.sha256

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <file.asice>")
    sys.exit(1)

filename = sys.argv[1]

try:
    archive = zipfile.ZipFile(filename, 'r')
except Exception as e:
    print(f"[-] Not a valid ASiC-E container (zip): {e}")
    sys.exit(1)

try:
    xml = archive.read('META-INF/signatures0.xml')
except KeyError:
    print("[-] Missing META-INF/signatures0.xml")
    sys.exit(1)

try:
    xmldoc = BeautifulSoup(xml, features="xml")
except Exception as e:
    print(f"[-] XML parsing error: {e}")
    sys.exit(1)

try:
    cert_b64 = xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents()
    signers_cert_der = codecs.decode(cert_b64, 'base64')
except Exception:
    node = xmldoc.find(lambda t: t.name and t.name.endswith('X509Certificate'))
    if not node:
        print("[-] Missing X509Certificate under Signature/KeyInfo/X509Data")
        sys.exit(1)
    signers_cert_der = b64decode_text(node.get_text())

print("[+] Signatory:", get_subject_cn(signers_cert_der))

signed_info = xmldoc.find(lambda t: t.name and t.name.endswith('SignedInfo'))
if signed_info is None:
    print("[-] Missing SignedInfo")
    sys.exit(1)

data_ref = None
for ref in signed_info.find_all(lambda t: t.name and t.name.endswith('Reference')):
    uri = ref.get('URI', '')
    if uri and not uri.startswith('#'):
        data_ref = ref
        break
if data_ref is None:
    print("[-] Missing Reference to signed file")
    sys.exit(1)

data_uri = data_ref.get('URI')
try:
    data_bytes = archive.read(data_uri)
except KeyError:
    print(f"[-] Signed file '{data_uri}' not found in container")
    sys.exit(1)

dm = data_ref.find(lambda t: t.name and t.name.endswith('DigestMethod'))
hash_fun_file = pick_hash(dm.get('Algorithm') if dm else None)
expected_dv_b64 = data_ref.find(lambda t: t.name and t.name.endswith('DigestValue'))
expected_dv_b64 = expected_dv_b64.get_text().encode('ascii') if expected_dv_b64 else b''

computed_dv_b64 = b64(hash_fun_file(data_bytes).digest())
if computed_dv_b64 != expected_dv_b64:
    print("[-] Signed file digest mismatch!")
    sys.exit(1)
print(f"[+] Signed file: {data_uri}")

sp_ref = None
for ref in signed_info.find_all(lambda t: t.name and t.name.endswith('Reference')):
    if ref.get('Type', '') == 'http://uri.etsi.org/01903#SignedProperties':
        sp_ref = ref
        break
if sp_ref is None:
    print("[-] Missing Reference for SignedProperties")
    sys.exit(1)

dm_sp = sp_ref.find(lambda t: t.name and t.name.endswith('DigestMethod'))
hash_fun_sp = pick_hash(dm_sp.get('Algorithm') if dm_sp else None)
sp_expected_b64 = sp_ref.find(lambda t: t.name and t.name.endswith('DigestValue'))
sp_expected_b64 = sp_expected_b64.get_text().encode('ascii') if sp_expected_b64 else b''

sp_c14n = canonicalize(xml, 'SignedProperties')
sp_computed_b64 = b64(hash_fun_sp(sp_c14n).digest())
if sp_computed_b64 != sp_expected_b64:
    print("[-] A wrong SignedProperties hash included under the signature!")
    sys.exit(1)

sc = xmldoc.find(lambda t: t.name and t.name.endswith('SigningCertificate'))
if sc:
    sc_dm = sc.find(lambda t: t.name and t.name.endswith('DigestMethod'))
    hash_fun_sc = pick_hash(sc_dm.get('Algorithm') if sc_dm else None)
    sc_dv = sc.find(lambda t: t.name and t.name.endswith('DigestValue'))
    sc_expected_b64 = sc_dv.get_text().encode('ascii') if sc_dv else b''
    sc_computed_b64 = b64(hash_fun_sc(signers_cert_der).digest())
    if sc_computed_b64 != sc_expected_b64:
        print("[-] A wrong certificate hash included under the signature!")
        sys.exit(1)

sigval_c14n = canonicalize(xml, 'SignatureValue')

ets = xmldoc.find(lambda t: t.name and t.name.endswith('SignatureTimeStamp'))
if ets is None:
    print("[-] Missing XAdES SignatureTimeStamp")
    sys.exit(1)
ets_val = ets.find(lambda t: t.name and t.name.endswith('EncapsulatedTimeStamp'))
if ets_val is None:
    print("[-] Missing EncapsulatedTimeStamp")
    sys.exit(1)

ts, ts_digestinfo = parse_tsa_response(b64decode_text(ets_val.get_text()))

h256 = hashlib.sha256(sigval_c14n).digest()
h384 = hashlib.sha384(sigval_c14n).digest()
if not (ts_digestinfo.endswith(h256) or ts_digestinfo.endswith(h384)):
    print("[-] Timestamp does not cover canonicalized SignatureValue!")
    sys.exit(1)

print("[+] Timestamped: %s +00:00" % (ts))

ocsp_vals = xmldoc.find(lambda t: t.name and t.name.endswith('OCSPValues'))
if ocsp_vals is None:
    print("[-] Missing OCSPValues")
    sys.exit(1)
ocsp_enc = ocsp_vals.find(lambda t: t.name and t.name.endswith('EncapsulatedOCSPValue'))
if ocsp_enc is None:
    print("[-] Missing EncapsulatedOCSPValue")
    sys.exit(1)

certID_serial, certStatus, thisUpdate = parse_ocsp_response(b64decode_text(ocsp_enc.get_text()))

signer_serial = decoder.decode(signers_cert_der)[0][0][1]
if int(signer_serial) != int(certID_serial):
    print("[-] OCSP response does not refer to the signer's certificate!")
    sys.exit(1)

if certStatus != 'good':
    print(f"[-] Certificate status is not good: {certStatus}")
    sys.exit(1)

if thisUpdate < ts:
    print("[-] OCSP thisUpdate precedes the timestamp!")
    sys.exit(1)

sig_method = signed_info.find(lambda t: t.name and t.name.endswith('SignatureMethod'))
hash_fun_sig = pick_hash(sig_method.get('Algorithm') if sig_method else None)

signed_info_c14n = canonicalize(xml, 'SignedInfo')
signed_hash = hash_fun_sig(signed_info_c14n).digest()

sigval_tag = xmldoc.find(lambda t: t.name and t.name.endswith('SignatureValue'))
signature_value = b64decode_text(sigval_tag.get_text())

if verify_ecdsa(signers_cert_der, signature_value, signed_hash):
    print("[+] Signature verification successful!")
else:
    print("[-] Signature verification failure!")

