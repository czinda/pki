#!/usr/bin/env python3
"""Probe PKCS #11 label lookup and NSS CA signing on a disposable software token."""

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

import pexpect
import pkcs11 as p11
from pkcs11.util.rsa import encode_rsa_public_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=30).stdout


def probe(directory, provider, module, control, jss, explicit_id, bind, installer):
    from datetime import datetime, timedelta, timezone

    pin = secrets.token_hex(12)
    if provider == 'softhsm':
        (directory / 'tokens').mkdir()
        conf = directory / 'softhsm.conf'
        conf.write_text(f'directories.tokendir = {directory}/tokens\n')
        os.environ['SOFTHSM2_CONF'] = str(conf)
        child = pexpect.spawn('softhsm2-util', ['--init-token', '--free', '--label', 'Ceremony'],
                              encoding='utf-8', timeout=10)
        for prompt in ['SO PIN:', 'SO PIN:', 'user PIN:', 'user PIN:']:
            child.expect_exact(prompt)
            child.sendline(pin)
        child.expect(pexpect.EOF)
        child.close()
        assert child.exitstatus == 0
    else:
        conf = directory / 'token.conf'
        conf.write_text(f'[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "{directory}/db"\n')
        os.environ['KRYOPTIC_CONF'] = str(conf)
        # OpenSC resolves env: references internally; never pass the PIN in argv.
        os.environ['PROBE_TOKEN_PIN'] = pin
        try:
            tool = ['pkcs11-tool', '--module', module, '--slot', '1', '--so-pin',
                    'env:PROBE_TOKEN_PIN']
            run(*tool, '--init-token', '--label', 'Ceremony')
            run(*tool, '--login', '--login-type', 'so', '--init-pin', '--pin', 'env:PROBE_TOKEN_PIN')
        finally:
            del os.environ['PROBE_TOKEN_PIN']
    token = p11.lib(module).get_token(token_label='Ceremony')
    attr = p11.Attribute
    query = {attr.CLASS: p11.ObjectClass.PRIVATE_KEY, attr.LABEL: 'ceremony-key'}
    with token.open(user_pin=pin, rw=True) as session:
        if bind or installer:
            # The decoy has an empty ID even when the intended key also has one.
            session.generate_keypair(p11.KeyType.RSA, 2048, label='decoy', store=True)
        pub, key = session.generate_keypair(p11.KeyType.RSA, 2048, id=explicit_id,
                                            label='ceremony-key',
                                            store=True, private_template={attr.EXTRACTABLE: False})
        if control:
            # Conventional NSS RSA key ID, used only on the disposable control pair.
            key[attr.ID] = pub[attr.ID] = hashlib.sha1(pub[attr.MODULUS]).digest()
        public = serialization.load_der_public_key(encode_rsa_public_key(pub))
    with token.open(user_pin=pin) as session:
        key, = session.get_objects(query)
        key_id = key[attr.ID]
        print(f'Initial private key ID: {key_id.hex() or "(empty)"}', flush=True)
        if not control and not explicit_id and key_id:
            raise ValueError('Provider assigned an ID: empty-ID case not exercised')
        if explicit_id and key_id != explicit_id:
            raise ValueError('Provider did not preserve the explicit ID')
        challenge = secrets.token_bytes(32)
        public.verify(key.sign(challenge, mechanism=p11.Mechanism.SHA256_RSA_PKCS),
                      challenge, padding.PKCS1v15(), hashes.SHA256())
        print('Signature by label verified', flush=True)

    parent = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dn = lambda s: x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, s)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(dn('Subordinate')).issuer_name(dn('Root'))
            .public_key(public).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(True, None), True).sign(parent, hashes.SHA256()))
    ca = directory / 'ca.pem'
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(dn('Leaf')).sign(leaf, hashes.SHA256())
    request = directory / 'request.der'
    request.write_bytes(csr.public_bytes(serialization.Encoding.DER))
    db = ['-d', 'sql:' + str(directory)]
    run('certutil', '-N', *db, '--empty-password')
    if b'token: Ceremony\n' not in run('modutil', '-dbdir', db[1], '-list'):
        run('modutil', '-dbdir', db[1], '-add', 'ceremony-module', '-libfile', module, '-force')
    def certutil(*options):
        with tempfile.TemporaryFile() as secret:
            secret.write((pin + '\n').encode())
            secret.seek(0)
            return subprocess.run(['certutil', *options, *db, '-f', f'/dev/fd/{secret.fileno()}'],
                                  pass_fds=(secret.fileno(),), capture_output=True, check=True,
                                  timeout=30).stdout

    if installer:
        import runpy
        from pki.nssdb import NSSDatabase

        root = (x509.CertificateBuilder().subject_name(dn('Root')).issuer_name(dn('Root'))
                .public_key(parent.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(True, None), True).sign(parent, hashes.SHA256()))
        verified = runpy.run_path(installer)['VerifiedCA'](cert, root, 'Ceremony', key_id)
        cfg = dict(pki_hsm_libfile=module, pki_token_password=pin,
                   pki_ca_signing_nickname='signing-cert', pki_cert_chain_nickname='offline-root')
        with os.fdopen(os.memfd_create('test-auth'), 'wb') as secret:
            secret.write(f'internal=\nhardware-Ceremony={pin}\n'.encode())
            secret.flush()
            nss = NSSDatabase(directory=str(directory),
                              password_conf=f'/proc/{os.getpid()}/fd/{secret.fileno()}')
            try:
                verified.install(nss, cfg)
            finally:
                nss.close()
    elif bind:
        from pkcs11.util.x509 import decode_x509_certificate
        template = decode_x509_certificate(cert.public_bytes(serialization.Encoding.DER))
        template.update({attr.TOKEN: True, attr.LABEL: 'signing-cert', attr.ID: key_id})
        with token.open(user_pin=pin, rw=True) as session:
            obj = session.create_object(template)
            assert obj[attr.ID] == key_id
    elif jss:
        run('pki', '-d', directory, '-f', '/dev/stdin', '--token', 'Ceremony',
            'nss-cert-import', '--cert', ca, '--format', 'PEM', '--trust', ',,', 'signing-cert',
            data=f'internal=\nhardware-Ceremony={pin}\n'.encode())
    else:
        certutil('-A', '-h', 'Ceremony', '-n', 'signing-cert', '-t', ',,', '-a', '-i', ca)
    with token.open(user_pin=pin) as session:
        key, = session.get_objects(query)
        assert key[attr.ID] == key_id
        if bind or installer:
            matches = list(session.get_objects({attr.CLASS: p11.ObjectClass.PRIVATE_KEY,
                                                attr.ID: key_id}))
            assert len(matches) == (1 if key_id else 2)
            print(f'Private keys sharing certificate ID: {len(matches)}', flush=True)
        for obj in session.get_objects({attr.CLASS: p11.ObjectClass.CERTIFICATE}):
            print(f'Imported token certificate label={obj[attr.LABEL]!r} ID={obj[attr.ID].hex()}')
    print(certutil('-L', '-h', 'Ceremony').decode(), flush=True)
    imported = certutil('-L', '-h', 'Ceremony', '-n', 'Ceremony:signing-cert', '-r')
    assert imported == cert.public_bytes(serialization.Encoding.DER)
    print('NSS read back exact CA certificate', flush=True)
    output = directory / 'leaf.der'
    signer = pexpect.spawn('certutil', ['-C', *db, '-h', 'Ceremony', '-c', 'Ceremony:signing-cert',
                                        '-i', str(request), '-o', str(output), '-m', '42',
                                        '-Z', 'SHA256'], encoding='utf-8', timeout=10)
    for _ in range(4):
        found = signer.expect([pexpect.EOF, r"Enter Password or Pin for .Ceremony.:"])
        if found == 0:
            break
        signer.sendline(pin)
    signer.close()
    if signer.exitstatus != 0:
        raise SystemExit('NSS leaf issuance failed: ' + signer.before.replace(pin, '[redacted]').strip())
    issued = output.read_bytes()
    signed = x509.load_der_x509_certificate(issued)
    signed.verify_directly_issued_by(cert)
    assert signed.public_key().public_numbers() == leaf.public_key().public_numbers()
    print('NSS issued a leaf by certificate nickname; signature verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', choices=['softhsm', 'kryoptic'])
    parser.add_argument('module')
    ids = parser.add_mutually_exclusive_group()
    ids.add_argument('--control', action='store_true', help='set a conventional nonempty ID')
    ids.add_argument('--id', type=bytes.fromhex, help='set an operator-supplied ID at generation')
    imports = parser.add_mutually_exclusive_group()
    imports.add_argument('--jss', action='store_true', help='use Dogtag CLI for certificate import')
    imports.add_argument('--bind', action='store_true',
                         help='create the certificate object with the selected key ID; include a decoy')
    imports.add_argument('--installer', metavar='PREISSUED_PY',
                         help='exercise the actual installer import with Dogtag NSS tools on Linux')
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            probe(Path(tmp), args.provider, args.module, args.control, args.jss, args.id, args.bind,
                  args.installer)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f'{exc.cmd[0]} {exc.cmd[1]} failed: {exc.stderr.decode().strip()}') from None
