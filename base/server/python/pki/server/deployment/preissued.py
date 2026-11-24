# SPDX-License-Identifier: GPL-2.0-only
"""Prototype: check a ceremony key without creating a Dogtag instance."""

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass(frozen=True)
class VerifiedCA:
    cert: x509.Certificate
    issuer: x509.Certificate
    token: str
    key_id: bytes

    @contextmanager
    def bind(self, cfg, nickname):
        """Bind the public certificate; keep its handle for rollback on failure."""
        import pkcs11
        from pkcs11.util.x509 import decode_x509_certificate

        attr = pkcs11.Attribute
        hsm = pkcs11.lib(cfg['pki_hsm_libfile']).get_token(token_label=self.token)
        with hsm.open(user_pin=cfg['pki_token_password'], rw=True) as session:
            self.prove_key(session)
            cert_class = {attr.CLASS: pkcs11.ObjectClass.CERTIFICATE}
            for selector in ({attr.LABEL: nickname}, {attr.ID: self.key_id}):
                if list(session.get_objects({**cert_class, **selector})):
                    raise ValueError('A certificate with this label or key ID already exists')
            template = decode_x509_certificate(self.cert.public_bytes(serialization.Encoding.DER))
            template.update({attr.ID: self.key_id, attr.LABEL: nickname,
                             attr.TOKEN: True, attr.PRIVATE: False})
            obj = session.create_object(template)
            try:
                if obj[attr.ID] != self.key_id:
                    raise ValueError('HSM did not preserve the certificate key ID')
                yield
            except Exception:
                obj.destroy()  # Only the certificate created by this call.
                raise

    def prove_key(self, session):
        import pkcs11
        keys = list(session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                                         pkcs11.Attribute.ID: self.key_id}))
        if len(keys) != 1:
            raise ValueError(f'Expected one private key on {self.token}; found {len(keys)}')
        if keys[0][pkcs11.Attribute.KEY_TYPE] != pkcs11.KeyType.RSA:
            raise ValueError('HSM key type does not match RSA certificate')
        challenge = b'Dogtag pkispawn key precheck\0' + secrets.token_bytes(32)
        signature = keys[0].sign(challenge, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)
        try:
            self.cert.public_key().verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as e:
            raise ValueError('Selected key does not match the issued CA certificate') from e

    def install(self, nssdb, cfg):
        nickname = cfg['pki_ca_signing_nickname']
        issuer_nickname = cfg['pki_cert_chain_nickname']
        if not nickname or not issuer_nickname or nickname == issuer_nickname:
            raise ValueError('Specify distinct signing certificate and root nicknames')
        # A fresh install must not replace objects already on a shared token.
        if nssdb.get_cert(nickname, token=self.token) or nssdb.get_cert(issuer_nickname):
            raise ValueError('CA signing or issuer certificate nickname already exists')
        pem = serialization.Encoding.PEM
        with self.bind(cfg, nickname):
            info = nssdb.get_cert_info(nickname, token=self.token)
            keys = nssdb.find_keys(nickname=nickname, token=self.token)['entries']
            if not info or info['object'] != self.cert or len(keys) != 1 or \
                    keys[0]['keyId'].lower() != '0x' + self.key_id.hex():
                raise ValueError('NSS did not bind the imported CA certificate to the ceremony key')
            nssdb.add_cert(issuer_nickname, cert_data=self.issuer.public_bytes(pem).decode(),
                           trust_attributes='CT,C,C')


def read_ca(path, setting):
    if not path:
        raise ValueError(f'Missing {setting}')
    data = Path(path).read_bytes()
    if data.count(b'-----BEGIN CERTIFICATE-----') != 1:
        raise ValueError(f'{setting} must contain one PEM CA certificate')
    cert = x509.load_pem_x509_certificate(data)
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    try:
        can_sign = cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    except x509.ExtensionNotFound:
        can_sign = True
    if not is_ca or not can_sign:
        raise ValueError(f'{setting} is not a signing CA certificate')
    return cert


def verify(cfg):
    """Check a direct offline-root issuance and an RSA key on the named token."""
    cert = read_ca(cfg.get('pki_ca_signing_cert_path'), 'pki_ca_signing_cert_path')
    issuer = read_ca(cfg.get('pki_cert_chain_path'), 'pki_cert_chain_path')
    if issuer.subject != issuer.issuer or cert.subject == issuer.subject:
        raise ValueError('Expected a distinct subordinate and its direct offline root issuer')
    public = cert.public_key()
    if not isinstance(public, rsa.RSAPublicKey):
        raise ValueError('This prototype requires an RSA CA signing key')
    token = cfg.get('pki_ca_signing_token')
    if not token or token.lower() == 'internal' or not cfg.get('pki_hsm_libfile'):
        raise ValueError('Specify an HSM module and an explicit CA signing token')
    key_id = cfg['pki_ca_signing_key_id']
    if not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', key_id):
        raise ValueError('pki_ca_signing_key_id must be 0x followed by whole hex bytes')
    key_id = bytes.fromhex(key_id[2:])
    pem = serialization.Encoding.PEM
    with tempfile.TemporaryDirectory() as directory:
        anchor = Path(directory) / 'issuer.pem'
        anchor.write_bytes(issuer.public_bytes(pem))
        result = subprocess.run(
            ['openssl', 'verify', '-trusted', str(anchor), '-x509_strict', '-check_ss_sig'],
            input=cert.public_bytes(pem), capture_output=True, check=False)
    if result.returncode:
        raise ValueError('CA certificate did not validate against the supplied issuer: ' +
                         result.stderr.decode(errors='replace').strip())
    try:
        import pkcs11
    except ImportError as e:
        raise ValueError('This prototype requires python-pkcs11') from e
    if not cfg.get('pki_token_password'):
        raise ValueError('Missing HSM token PIN')
    verified = VerifiedCA(cert, issuer, token, key_id)
    try:
        hsm = pkcs11.lib(cfg['pki_hsm_libfile']).get_token(token_label=token)
        with hsm.open(user_pin=cfg['pki_token_password'], rw=False) as session:
            verified.prove_key(session)
    except pkcs11.PKCS11Error as e:
        raise ValueError(f'HSM precheck failed for {token}: {type(e).__name__}') from e
    return verified
