import hashlib
import json
import libknot.control
import logging
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


logger = logging.getLogger(__name__)

class EMKnot:
    def __init__(self, socket_path: str = '/var/run/knot/knot.sock', timeout: int = 60, max_retries: int = 3):
        self.ctl = libknot.control.KnotCtl()
        self.ctl.connect(socket_path)
        self.ctl.set_timeout(timeout)
        self.max_retries = max_retries

    def __del__(self):
        self.ctl.send(libknot.control.KnotCtlType.END)
        self.ctl.close()

    def _subnodes(self, **subdomain):
        yield '_25._tcp.' + subdomain['mail']
        yield '_465._tcp.' + subdomain['smtp']
        yield '_587._tcp.' + subdomain['smtp']
        yield '_993._tcp.' + subdomain['imap']
        yield '_995._tcp.' + subdomain['pop3']

        yield '_443._tcp.' + subdomain['mail']
        for subdomain in ['openpgpkey', 'wkd', 'autoconfig', 'autodiscover', 'mta_sts', 'imap', 'pop3', 'smtp', 'rspamd', 'dav', 'webmail']:
            yield '_443._tcp.' + subdomain

    def add_tlsa(self, zone: str, cert_path: str, *args, **kwargs):
        """Adds a TLSA record of the form '3 1 1 {cert sha256 digest}'"""
        with open(cert_path, 'rb') as f:
            cert = f.read()
        cert_pem = x509.load_pem_x509_certificate(cert, default_backend())
        cert_pubkey = cert_pem.public_key()
        cert_pubkey_bytes = cert_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        cert_digest256 = hashlib.sha256(cert_pubkey_bytes).hexdigest()
        cert_digest512 = hashlib.sha512(cert_pubkey_bytes).hexdigest()

        for i in range(self.max_retries):
            try:
                self.ctl.send_block(cmd='zone-begin', zone=zone)
                break
            except libknot.control.KnotCtlError as exc:
                logger.warning(f'Error while starting transaction for zone {zone}: {exc}')
                self.ctl.send_block(cmd='zone-abort', zone=zone)
        else:
            raise RuntimeError(f'Could not start transaction for zone {zone}')

        for snode in self._subnodes(*args, **kwargs):
            try:
                self.ctl.send_block(cmd='zone-unset', zone=zone, owner=snode, rtype='TLSA')
            except libknot.control.KnotCtlError as exc:
                log.warning(f'Error while deleting current TLSA record: {exc}')

            try:
                for data in [f'3 1 1 {cert_digest256}', f'3 1 2 {cert_digest512}']:
                    self.ctl.send_block(cmd='zone-set', zone=zone, owner=snode, rtype='TLSA', ttl='10800', data=data)
            except libknot.control.KnotCtlError as exc:
                log.warning(f'Error while adding new TLSA record: {exc}')

        self.ctl.send_block(cmd='zone-commit', zone='bsd.ac.')


if __name__ == '__main__':
    emk = EMKnot()
    emk.add_tlsa(sys.argv[1], sys.argv[2], mail='mail', openpgpkey='openpgpkey', wkd='wkd', autoconfig='autoconfig', autodiscover='autodiscover', mta_sts='mta-sts', imap='imap', pop3='pop3', smtp='smtp', rspamd='rspamd', dav='dav', webmail='webmail')
