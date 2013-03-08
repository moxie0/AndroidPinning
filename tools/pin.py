#!/usr/bin/env python
"""pin generates SPKI pin hashes from X.509 PEM files."""

__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2011 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

If you need this to be something other than GPL, send me an email.
"""

from M2Crypto import X509
import sys, binascii, hashlib

def main(argv):
    if len(argv) < 1:
        print "Usage: pin.py <certificate_path>"
        return

    x509        = X509.load_cert(argv[0])
    spki        = x509.get_pubkey()
    encodedSpki = spki.as_der()

    digest = hashlib.sha1()
    digest.update(encodedSpki)

    print "Calculating PIN for certificate: " + x509.get_subject().as_text()
    print "Pin Value: " + binascii.hexlify(digest.digest())

if __name__ == '__main__':
    main(sys.argv[1:])
