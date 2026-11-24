"""SoftHSM integration test. Set SOFTHSM2_MODULE to the test module path."""

import datetime
import os
from pathlib import Path
import runpy
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def issue(subject, issuer, public_key, signer, ca=True):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca, None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False,
                                         ca, ca, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signer.public_key()), False)
            .sign(signer, hashes.SHA256()))


@pytest.mark.skipif(not os.environ.get('SOFTHSM2_MODULE'), reason='requires SoftHSM')
def test_ceremony_handoff(tmp_path, monkeypatch):
    import pexpect
    import pkcs11
    from pkcs11.util.rsa import encode_rsa_public_key

    # Run against a private token store, never the host's configured tokens.
    store = tmp_path / 'tokens'
    store.mkdir()
    conf = tmp_path / 'softhsm.conf'
    conf.write_text(f'directories.tokendir = {store}\n')
    monkeypatch.setenv('SOFTHSM2_CONF', str(conf))
    pin = secrets.token_hex(12)
    child = pexpect.spawn('softhsm2-util', ['--init-token', '--free', '--label', 'Ceremony'],
                          encoding='utf-8', timeout=10)
    for prompt in ['SO PIN:', 'SO PIN:', 'user PIN:', 'user PIN:']:
        child.expect_exact(prompt)
        child.sendline(pin)
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0

    module = os.environ['SOFTHSM2_MODULE']
    token = pkcs11.lib(module).get_token(token_label='Ceremony')
    with token.open(user_pin=pin, rw=True) as session:
        pub, key = session.generate_keypair(pkcs11.KeyType.RSA, 2048, id=b'\x00\x12',
                                            store=True, private_template={
                                                pkcs11.Attribute.EXTRACTABLE: False})
        assert not key[pkcs11.Attribute.EXTRACTABLE]
        public = serialization.load_der_public_key(encode_rsa_public_key(pub))
        before = len(list(session.get_objects()))

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Offline root')])
    sub = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Subordinate')])
    pem = serialization.Encoding.PEM
    anchor = tmp_path / 'root.pem'
    anchor.write_bytes(issue(root, root, root_key.public_key(), root_key).public_bytes(pem))
    cert = tmp_path / 'sub.pem'
    good = issue(sub, root, public, root_key).public_bytes(pem)
    cert.write_bytes(good)
    cfg = dict(pki_hsm_libfile=module, pki_token_password=pin,
               pki_ca_signing_token='Ceremony', pki_ca_signing_key_id='0x0012',
               pki_ca_signing_cert_path=str(cert), pki_cert_chain_path=str(anchor))
    path = (Path(__file__).resolve().parents[3] /
            'base/server/python/pki/server/deployment/preissued.py')
    verify = runpy.run_path(str(path))['verify']
    verified = verify(cfg)
    with pytest.raises(ValueError, match='private key'):
        verify(dict(cfg, pki_ca_signing_key_id='0x12'))
    cert.write_bytes(issue(sub, root, root_key.public_key(), root_key).public_bytes(pem))
    with pytest.raises(ValueError, match='match'):
        verify(cfg)
    cert.write_bytes(issue(sub, root, public, root_key, ca=False).public_bytes(pem))
    with pytest.raises(ValueError, match='CA certificate'):
        verify(cfg)
    cert.write_bytes(good)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    anchor.write_bytes(issue(root, root, other.public_key(), other).public_bytes(pem))
    with pytest.raises(ValueError, match='issuer'):
        verify(cfg)
    with token.open(user_pin=pin) as session:
        assert len(list(session.get_objects())) == before
    anchor.write_bytes(issue(root, root, root_key.public_key(), root_key).public_bytes(pem))
    with pytest.raises(RuntimeError, match='NSS readback'):
        with verified.bind(cfg, 'sub-ca'):
            raise RuntimeError('NSS readback failed')
    with token.open(user_pin=pin) as session:
        assert len(list(session.get_objects())) == before
    # Retry with the same key after rollback.
    with verified.bind(cfg, 'sub-ca'):
        with token.open(user_pin=None) as session:
            obj, = session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                                        pkcs11.Attribute.LABEL: 'sub-ca'})
            assert obj[pkcs11.Attribute.ID] == b'\x00\x12'
            assert obj[pkcs11.Attribute.VALUE] == verified.cert.public_bytes(serialization.Encoding.DER)
    with pytest.raises(ValueError, match='already exists'):
        with verified.bind(cfg, 'sub-ca'):
            pytest.fail('duplicate certificate accepted')
    with token.open(user_pin=pin, rw=True) as session:
        session.generate_keypair(pkcs11.KeyType.RSA, 2048, id=b'\x00\x12', store=True)
    with pytest.raises(ValueError, match='found 2'):
        verify(cfg)
