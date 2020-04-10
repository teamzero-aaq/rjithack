#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import datetime
import sys

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf


# import logging
# logging.basicConfig(level=logging.DEBUG)

def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        b'sigflags': 3,
        # b'sigpage': 0,
        b'sigbutton': True,
        b'signature_img': b'sign.png',
        b'contact': b'sohil.l@somaiya.edu',
        b'location': b'India',
        b'signingdate': date.encode(),
        b'reason': b'Verified Document',
        b'signature': b'Approved By Goverment',
        b'signaturebox': (470, 0, 570, 100),
    }
    with open('Key.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'Sky@76445', backends.default_backend())
    fname = 'resume.pdf'
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         p12[0],
                         p12[1],
                         p12[2],
                         'sha256'
                         )
    fname = fname.replace('.pdf', '-signed-cms.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
