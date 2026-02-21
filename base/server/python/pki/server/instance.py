# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import

import functools
import inspect
import io
import logging
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from lxml import etree

import pki
import pki.cert
import pki.nssdb
import pki.util
import pki.server

logger = logging.getLogger(__name__)

parser = etree.XMLParser(remove_blank_text=True)


class QuarkusServerConfig:
    """
    Lightweight server configuration for Quarkus instances.
    Provides get_http_port() and get_https_port() methods
    to replace Tomcat's ServerConfig (server.xml).
    """

    def __init__(self, http_port=None, https_port=None):
        self.http_port = http_port or str(pki.server.DEFAULT_HTTP_PORT)
        self.https_port = https_port or str(pki.server.DEFAULT_HTTPS_PORT)

    def get_http_port(self):
        return self.http_port

    def get_https_port(self):
        return self.https_port


@functools.total_ordering
class PKIInstance(pki.server.PKIServer):

    REGISTRY_FILE = pki.server.PKIServer.SHARE_DIR + '/setup/pkidaemon_registry'
    UNIT_FILE = pki.server.LIB_SYSTEMD_DIR + '/system/pki-quarkusd@.service'
    TARGET_FILE = pki.server.LIB_SYSTEMD_DIR + '/system/pki-quarkusd.target'
    TARGET_WANTS = pki.server.ETC_SYSTEMD_DIR + '/system/pki-quarkusd.target.wants'

    def __init__(self,
                 name,
                 instance_type='pki-quarkusd',
                 user='pkiuser',
                 group='pkiuser',
                 version=10):

        super().__init__(name, instance_type, user, group)

        self.version = version

        self.external_certs = []

        # The standard conf dir at /var/lib/pki/<instance>/conf
        # will be a link to the actual folder at /etc/pki/<instance>.
        self._conf_dir = os.path.join(pki.server.PKIServer.CONFIG_DIR, self.name)

        # The standard conf dir at /var/lib/pki/<instance>/logs
        # will be a link to the actual folder at /var/log/pki/<instance>.
        self._logs_dir = os.path.join(pki.server.PKIServer.LOG_DIR, self.name)

        self.with_maven_deps = False

    def __eq__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name == other.name and
                self.version == other.version)

    def __ne__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name < other.name or
                self.version < other.version)

    def __hash__(self):
        return hash((self.name, self.version))

    @property
    def base_dir(self):
        if self.version < 10:
            return os.path.join(pki.BASE_DIR, self.name)
        return os.path.join(pki.server.PKIServer.BASE_DIR, self.name)

    @property
    def service_conf(self):
        return os.path.join(pki.server.SYSCONFIG_DIR, self.name)

    @property
    def server_cert_nick_conf(self):
        logger.warning(
            '%s:%s: The PKIInstance.server_cert_nick_conf() has '
            'been deprecated (https://github.com/dogtagpki/pki/wiki/PKI-10.9-Python-Changes).',
            inspect.stack()[1].filename, inspect.stack()[1].lineno)
        return os.path.join(self.conf_dir, 'serverCertNick.conf')

    def get_sslserver_cert_nickname(self):
        """
        Get the SSL server cert nickname from serverCertNick.conf.
        """
        server_cert_nick_conf = os.path.join(self.conf_dir, 'serverCertNick.conf')
        if not os.path.exists(server_cert_nick_conf):
            return None
        with open(server_cert_nick_conf, 'r', encoding='utf-8') as f:
            return f.read().strip()

    def set_sslserver_cert_nickname(self, nickname, token=None):
        """
        Store the SSL server cert nickname in serverCertNick.conf.
        """
        if pki.nssdb.internal_token(token):
            fullname = nickname
        else:
            fullname = token + ':' + nickname

        server_cert_nick_conf = os.path.join(self.conf_dir, 'serverCertNick.conf')
        logger.info('Updating %s', server_cert_nick_conf)

        with open(server_cert_nick_conf, 'w', encoding='utf-8') as f:
            f.write(fullname + '\n')

        self.chown(server_cert_nick_conf)
        os.chmod(server_cert_nick_conf, pki.server.DEFAULT_FILE_MODE)

    def get_server_config(self):
        """
        Return a QuarkusServerConfig with HTTP/HTTPS ports.

        Reads ports from the instance's CS.cfg or defaults.
        """
        http_port = str(pki.server.DEFAULT_HTTP_PORT)
        https_port = str(pki.server.DEFAULT_HTTPS_PORT)

        # Try to read ports from subsystem CS.cfg
        for subsystem in self.get_subsystems():
            port = subsystem.config.get('proxy.unsecurePort')
            if port:
                http_port = port
            port = subsystem.config.get('proxy.securePort')
            if port:
                https_port = port
            # Also check the standard port settings
            port = subsystem.config.get('service.unsecurePort')
            if port:
                http_port = port
            port = subsystem.config.get('service.securePort')
            if port:
                https_port = port
            break  # use first subsystem

        return QuarkusServerConfig(http_port=http_port, https_port=https_port)

    @property
    def banner_file(self):
        return os.path.join(self.conf_dir, 'banner.txt')

    @property
    def external_certs_conf(self):
        return os.path.join(self.conf_dir, 'external_certs.conf')

    @property
    def registry_dir(self):
        return os.path.join(pki.server.PKIServer.REGISTRY_DIR, 'quarkus', self.name)

    @property
    def registry_file(self):
        return os.path.join(self.registry_dir, self.name)

    @property
    def unit_file(self):
        return PKIInstance.TARGET_WANTS + '/%s.service' % self.service_name

    def start(self, subsystem=None, wait=False, max_wait=60, timeout=None):
        """Start Quarkus service(s).

        If subsystem is specified, start only that subsystem's service.
        Otherwise, start all loaded subsystem services.
        """
        if subsystem:
            super().start(subsystem=subsystem, wait=wait, max_wait=max_wait, timeout=timeout)
        else:
            for sub in self.get_subsystems():
                super().start(subsystem=sub.name, wait=wait, max_wait=max_wait, timeout=timeout)

    def stop(self, subsystem=None, wait=False, max_wait=60, timeout=None):
        """Stop Quarkus service(s).

        If subsystem is specified, stop only that subsystem's service.
        Otherwise, stop all loaded subsystem services.
        """
        if subsystem:
            super().stop(subsystem=subsystem, wait=wait, max_wait=max_wait, timeout=timeout)
        else:
            for sub in self.get_subsystems():
                super().stop(subsystem=sub.name, wait=wait, max_wait=max_wait, timeout=timeout)

    def enable(self, subsystem=None):
        """Enable Quarkus service(s).

        If subsystem is specified, enable only that subsystem's service.
        Otherwise, enable all loaded subsystem services.
        """
        if subsystem:
            super().enable(subsystem=subsystem)
        else:
            for sub in self.get_subsystems():
                super().enable(subsystem=sub.name)

    def disable(self, subsystem=None):
        """Disable Quarkus service(s).

        If subsystem is specified, disable only that subsystem's service.
        Otherwise, disable all loaded subsystem services.
        """
        if subsystem:
            super().disable(subsystem=subsystem)
        else:
            for sub in self.get_subsystems():
                super().disable(subsystem=sub.name)

    def is_active(self, subsystem=None):
        """Check if Quarkus service(s) are active.

        If subsystem is specified, check only that subsystem's service.
        Otherwise, return True if any loaded subsystem service is active.
        """
        if subsystem:
            service = self.get_subsystem_service_name(subsystem)
            cmd = ['systemctl', '--quiet', 'is-active', '%s.service' % service]
            logger.debug('Command: %s', ' '.join(cmd))
            return subprocess.call(cmd) == 0

        for sub in self.get_subsystems():
            service = self.get_subsystem_service_name(sub.name)
            cmd = ['systemctl', '--quiet', 'is-active', '%s.service' % service]
            logger.debug('Command: %s', ' '.join(cmd))
            if subprocess.call(cmd) == 0:
                return True
        return False

    def create(self, force=False):

        super().create(force=force)

        self.create_registry()

        self.symlink(PKIInstance.UNIT_FILE, self.unit_file, exist_ok=True)

    def create_libs(self, force=False):

        if not self.with_maven_deps:
            super().create_libs(force=force)
            return

        logger.info('Updating Maven dependencies')

        cmd = [
            'mvn',
            '-f', '/usr/share/pki/pom.xml',
            'dependency:resolve'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

        repo_dir = '%s/.m2/repository' % pathlib.Path.home()

        pom_xml = '/usr/share/pki/pom.xml'
        logger.info('Loading %s', pom_xml)

        document = etree.parse(pom_xml, parser)
        project = document.getroot()

        xmlns = 'http://maven.apache.org/POM/4.0.0'

        groupId = project.findtext('{%s}groupId' % xmlns)
        logger.info('Group: %s', groupId)

        artifactId = project.findtext('{%s}artifactId' % xmlns)
        logger.info('Artifact: %s', artifactId)

        version = project.findtext('{%s}version' % xmlns)
        logger.info('Version: %s', version)

        dependencies = project.findall('{%s}dependencies/{%s}dependency' % (xmlns, xmlns))

        self.makedirs(self.lib_dir, exist_ok=True)
        self.makedirs(self.common_dir, exist_ok=True)
        self.makedirs(self.common_lib_dir, exist_ok=True)

        for dependency in dependencies:

            groupId = dependency.findtext('{%s}groupId' % xmlns)
            artifactId = dependency.findtext('{%s}artifactId' % xmlns)
            version = dependency.findtext('{%s}version' % xmlns)
            fileType = dependency.findtext('{%s}type' % xmlns, default='jar')

            groupDir = groupId.replace('.', '/')
            directory = os.path.join(repo_dir, groupDir, artifactId, version)
            filename = artifactId + '-' + version + '.' + fileType
            source = os.path.join(directory, filename)

            # install Maven libraries in common/lib except slf4j
            if artifactId in ['slf4j-api', 'slf4j-jdk14']:
                dest = os.path.join(self.lib_dir, filename)
            else:
                dest = os.path.join(self.common_lib_dir, filename)

            logger.info('Copying %s to %s', source, dest)
            self.copy(source, dest, exist_ok=True, force=force)

        common_lib_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, 'server', 'common', 'lib')

        # install PKI libraries in common/lib
        for filename in [
                'jss.jar',
                'ldapjdk.jar',
                'pki-common.jar']:

            source = os.path.join(common_lib_dir, filename)
            dest = os.path.join(self.common_lib_dir, filename)

            self.symlink(source, dest, exist_ok=True)

    def create_registry(self):

        # Create instance registry folder at
        # /etc/sysconfig/pki/quarkus/<instance>

        self.makedirs(self.registry_dir, exist_ok=True)

        # Copy /usr/share/pki/setup/pkidaemon_registry
        # to /etc/sysconfig/pki/quarkus/<instance>/<instance>

        self.copyfile(
            PKIInstance.REGISTRY_FILE,
            self.registry_file,
            params={
                'pki_user': self.user,
                'pki_group': self.group,
                'pki_instance_name': self.name,
                'pki_instance_path': self.base_dir
            },
            exist_ok=True)

    def load(self):

        super().load()

        # load UID and GID
        if os.path.exists(self.registry_file):

            logger.info('Loading instance registry: %s', self.registry_file)

            with open(self.registry_file, 'r', encoding='utf-8') as registry:
                lines = registry.readlines()

            for line in lines:
                m = re.search('^PKI_USER=(.*)$', line)
                if m:
                    self.user = m.group(1)
                    logger.debug('- user: %s', self.user)

                m = re.search('^PKI_GROUP=(.*)$', line)
                if m:
                    self.group = m.group(1)
                    logger.debug('- group: %s', self.group)

        self.load_external_certs()

    def load_external_certs(self):
        for external_cert in PKIInstance.load_external_certs_conf(self.external_certs_conf):
            self.add_external_cert(external_cert.nickname, external_cert.token)

    def remove(self, remove_conf=False, remove_logs=False, force=False):

        if os.path.exists(self.unit_file):
            logger.info('Removing %s', self.unit_file)
            pki.util.unlink(self.unit_file, force=force)

        self.remove_registry(force=force)

        super().remove(
            remove_conf=remove_conf,
            remove_logs=remove_logs,
            force=force)

    def remove_libs(self, force=False):

        logger.info('Removing %s', self.common_dir)
        pki.util.rmtree(self.common_dir, force=force)

        logger.info('Removing %s', self.lib_dir)
        if os.path.islink(self.lib_dir):
            pki.util.unlink(self.lib_dir, force=force)
        else:
            pki.util.rmtree(self.lib_dir, force=force)

    def remove_registry(self, force=False):

        # Remove /etc/sysconfig/pki/quarkus/<instance>/<instance>

        logger.info('Removing %s', self.registry_file)
        pki.util.remove(self.registry_file, force=force)

        # Remove instance registry folder at
        # /etc/sysconfig/pki/quarkus/<instance>

        logger.info('Removing %s', self.registry_dir)
        pki.util.rmtree(self.registry_dir, force=force)

    @staticmethod
    def load_external_certs_conf(conf_file):

        if not os.path.exists(conf_file):
            return []

        logger.info('Loading external certs from %s', conf_file)
        lines = open(conf_file, encoding='utf-8').read().splitlines()

        tmp_certs = {}
        for line in lines:

            m = re.search('(\\d+)\\.(\\w+)=(.*)', line)
            if not m:
                raise pki.PKIException('Error parsing %s' % conf_file)

            indx = m.group(1)
            attr = m.group(2)
            value = m.group(3)

            if attr == 'nickname':
                logger.debug('- %s', value)

            if indx not in tmp_certs:
                tmp_certs[indx] = pki.server.ExternalCert()

            setattr(tmp_certs[indx], attr, value)

        return tmp_certs.values()

    @staticmethod
    def store_external_certs_conf(conf_file, external_certs):

        logger.info('Storing external certs into %s', conf_file)

        with open(conf_file, 'w', encoding='utf-8') as f:
            indx = 0
            for cert in external_certs:

                logger.debug('- %s', cert.nickname)

                f.write('%s.nickname=%s\n' % (str(indx), cert.nickname))
                f.write('%s.token=%s\n' % (str(indx), cert.token))
                indx += 1

    def external_cert_exists(self, nickname, token):
        for cert in self.external_certs:
            if cert.nickname == nickname and cert.token == token:
                return True
        return False

    def add_external_cert(self, nickname, token):
        if self.external_cert_exists(nickname, token):
            return
        self.external_certs.append(pki.server.ExternalCert(nickname, token))

    def delete_external_cert(self, nickname, token):
        for cert in self.external_certs:
            if cert.nickname == nickname and cert.token == token:
                self.external_certs.remove(cert)

    def store_external_certs(self):

        if len(self.external_certs) == 0:
            logger.info('Removing %s', self.external_certs_conf)
            pki.util.remove(self.external_certs_conf)
            return

        PKIInstance.store_external_certs_conf(self.external_certs_conf, self.external_certs)

    def export_external_certs(self, pkcs12_file, pkcs12_password_file,
                              append=False):
        for cert in self.external_certs:
            nickname = cert.nickname
            token = pki.nssdb.normalize_token(cert.token)

            nssdb_password = self.get_token_password(token)

            tmpdir = tempfile.mkdtemp()

            try:
                nssdb_password_file = os.path.join(tmpdir, 'password.txt')
                with open(nssdb_password_file, 'w', encoding='utf-8') as f:
                    f.write(nssdb_password)

                # add the certificate, key, and chain
                cmd = [
                    'pki',
                    '-d', self.nssdb_dir,
                    '-C', nssdb_password_file
                ]

                if token:
                    cmd.extend(['--token', token])

                cmd.extend([
                    'pkcs12-cert-import',
                    '--pkcs12-file', pkcs12_file,
                    '--pkcs12-password-file', pkcs12_password_file,
                ])

                if append:
                    cmd.extend(['--append'])

                cmd.extend([
                    nickname
                ])

                logger.debug('Command: %s', ' '.join(cmd))

                subprocess.check_call(cmd)

            finally:
                shutil.rmtree(tmpdir)

    def banner_installed(self):
        return os.path.exists(self.banner_file)

    def get_banner(self):
        with io.open(self.banner_file, encoding='utf-8') as f:
            return f.read().strip()

    def validate_banner(self):

        if not self.banner_installed():
            return

        banner = self.get_banner()

        if not banner:
            raise Exception('Banner is empty')

    def __repr__(self):
        if self.version == 9:
            return "Dogtag 9 " + self.name
        return self.name

    def cert_del(self, cert_id, remove_key=False):
        """
        Delete a cert from NSS db

        :param cert_id: Cert ID
        :type cert_id: str
        :param remove_key: Remove associate private key
        :type remove_key: bool
        """

        subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)

        if not subsystem_name:
            subsystem_name = self.get_subsystems()[0].name

        subsystem = self.get_subsystem(subsystem_name)

        cert = subsystem.get_subsystem_cert(cert_tag)
        nssdb = self.open_nssdb()

        try:
            logger.debug('Removing %s certificate from NSS database from '
                         'subsystem %s in instance %s', cert_tag, subsystem.name, self.name)
            nssdb.remove_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                remove_key=remove_key)
        finally:
            nssdb.close()

    def cert_import(
            self,
            cert_id=None,
            cert_file=None,
            token=None,
            nickname=None):
        """
        Import cert from cert_file into NSS db with appropriate trust

        :param cert_id: Cert ID
        :type cert_id: str
        :param cert_file: Cert file to be imported into NSS db
        :type cert_file: str
        :param token: Token to store the certificate
        :type token: str
        :param nickname: Certificate nickname
        :type nickname: str
        :return: None
        :rtype: None
        """

        if cert_id:
            if not cert_file:
                # If cert_file is not provided, load the cert from
                # /var/lib/pki/<instance>/conf/certs/<cert_id>.crt
                cert_file = self.cert_file(cert_id)
            logger.debug('Importing cert %s from %s', cert_id, cert_file)
        else:
            if not cert_file:
                raise pki.server.PKIServerException('Missing certificate ID or file')
            logger.debug('Importing cert from %s', cert_file)

        if not os.path.isfile(cert_file):
            raise pki.server.PKIServerException('File does not exist: %s' % cert_file)

        if cert_id:
            subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)
        else:
            subsystem_name = None
            cert_tag = None

        logger.debug('- subsystem: %s', subsystem_name)
        logger.debug('- cert tag: %s', cert_tag)

        if subsystem_name:
            # if cert ID contains subsystem name, get that subsystem
            subsystem = self.get_subsystem(subsystem_name)
        else:
            # if cert ID does not contain subsystem name (i.e. sslserver, subsystem),
            # get the first available subsystem
            subsystems = self.get_subsystems()
            if len(subsystems) > 0:
                subsystem = subsystems[0]
            else:
                subsystem = None

        if subsystem and cert_tag:
            # if the subsystem exists, use the nickname and token
            # specified in CS.cfg
            cert_info = subsystem.get_subsystem_cert(cert_tag)
            nickname = cert_info['nickname']
            token = cert_info['token']
        else:
            # if the subsystem does not exist, use the specified
            # nickname and token
            if not nickname and cert_id:
                # if nickname not specified, use the cert ID
                nickname = cert_id

        # audit and CA signing cert require special flags set in NSSDB
        trust_attributes = None
        if cert_id == 'ca_signing':
            trust_attributes = 'CT,C,C'
        elif cert_tag == 'audit_signing':
            trust_attributes = ',,P'

        logger.debug('- trust flags: %s', trust_attributes)

        nssdb = self.open_nssdb()

        try:
            logger.debug('Checking existing cert %s', nickname)

            if nssdb.get_cert(
                    nickname=nickname,
                    token=token):
                raise pki.server.PKIServerException(
                    'Certificate already exists: %s' % nickname)

            logger.debug('Importing cert %s', nickname)

            nssdb.add_cert(
                nickname=nickname,
                token=token,
                cert_file=cert_file,
                trust_attributes=trust_attributes)

        finally:
            nssdb.close()

    def cert_request(self, cert_id, subject_dn, token=None, ext_conf=None):

        token = pki.nssdb.normalize_token(token)
        csr_file = self.csr_file(cert_id)

        cmd = [
            '/usr/sbin/runuser',
            '-u', self.user, '--',
            'pki',
            '-d', self.nssdb_dir,
            '-f', self.password_conf
        ]

        if token:
            cmd.extend(['--token', token])

        cmd.extend([
            'nss-cert-request',
            '--subject', subject_dn,
            '--csr', csr_file
        ])

        if ext_conf:
            cmd.extend(['--ext', ext_conf])

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))

        subprocess.check_call(cmd)

    def cert_create(
            self, cert_id=None,
            username=None, password=None,
            client_cert=None, client_nssdb=None,
            client_nssdb_pass=None, client_nssdb_pass_file=None,
            serial=None, temp_cert=False, renew=False, output=None,
            secure_port='8443',
            token=None,
            issuer=None,
            ext_conf=None):
        """
        Create a new cert for the cert_id provided

        :param cert_id: New cert's ID
        :type cert_id: str
        :param username: Username (must also supply password)
        :type username: str
        :param password: Password (must also supply username)
        :type password: str
        :param client_cert: Client cert nickname
        :type client_cert: str
        :param client_nssdb: Path to nssdb
        :type client_nssdb: str
        :param client_nssdb_pass: Password to the nssdb
        :type client_nssdb_pass: str
        :param client_nssdb_pass_file: File containing nssdb's password
        :type client_nssdb_pass_file: str
        :param serial: Serial number of the cert to be renewed.  If creating
                       a temporary certificate (temp_cert == True), the serial
                       number will be reused.  If not supplied, the cert_id is
                       used to look it up.
        :type serial: str
        :param temp_cert: Whether new cert is a temporary cert
        :type temp_cert: bool
        :param renew: Whether to place a renewal request to ca
        :type renew: bool
        :param output: Path to which new cert needs to be written to
        :type output: str
        :param secure_port: Secure port number in case of renewing a certificate
        :type secure_port: str
        :param token: Token that stores the signing key
        :type token: str
        :param issuer: Issuer certificate nickname
        :type issuer: str
        :param ext_conf: Configuration file for certificate extension
        :type ext_conf: str
        :return: None
        :rtype: None
        :raises pki.server.PKIServerException

        Either supply both username and password, or supply
        client_cert and (client_nssdb_pass or client_nssdb_pass_file).

        Note that client_nssdb should be specified in either case, as it
        contains the CA Certificate.
        """

        if not temp_cert and not renew:
            # creating permanent cert

            token = pki.nssdb.normalize_token(token)
            csr_file = self.csr_file(cert_id)
            cert_file = self.cert_file(cert_id)

            cmd = [
                '/usr/sbin/runuser',
                '-u', self.user, '--',
                'pki',
                '-d', self.nssdb_dir,
                '-f', self.password_conf
            ]

            if token:
                cmd.extend(['--token', token])

            cmd.extend([
                'nss-cert-issue',
                '--csr', csr_file,
                '--cert', cert_file
            ])

            if issuer:
                cmd.extend(['--issuer', issuer])

            if ext_conf:
                cmd.extend(['--ext', ext_conf])

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.check_call(cmd)

            return

        if not temp_cert:
            # For permanent certificate, password of either NSS DB OR agent is required.
            if not client_nssdb_pass and not client_nssdb_pass_file and not password:
                raise Exception('NSS database or agent password is required.')

        nssdb = self.open_nssdb()
        tmpdir = tempfile.mkdtemp()
        subsystem = None  # used for system certs

        try:
            if cert_id:
                new_cert_file = output if output else self.cert_file(cert_id)

                subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)
                if not subsystem_name:
                    subsystem_name = self.get_subsystems()[0].name
                subsystem = self.get_subsystem(subsystem_name)

                if serial is None:
                    # If admin doesn't provide a serial number, set the serial to
                    # the same serial number available in the nssdb
                    serial = subsystem.get_subsystem_cert(cert_tag)["serial_number"]

            else:
                if serial is None:
                    raise pki.server.PKIServerException(
                        "Must provide either 'cert_id' or 'serial'")
                if output is None:
                    raise pki.server.PKIServerException(
                        "Must provide 'output' when renewing by serial")
                if temp_cert:
                    raise pki.server.PKIServerException(
                        "'temp_cert' must be used with 'cert_id'")
                new_cert_file = output

            if temp_cert:
                assert subsystem is not None  # temp_cert only supported with cert_id

                logger.info('Creating temp cert for %s', cert_id)

                # Create Temp Cert and write it to new_cert_file
                subsystem.temp_cert_create(nssdb, cert_tag, serial, new_cert_file)

                logger.info('Storing temp cert into %s', new_cert_file)

            else:
                # Create permanent certificate
                if not renew:
                    # TODO: Support rekey
                    raise pki.server.PKIServerException('Rekey is not supported yet.')

                logger.debug('Setting up secure connection to CA')
                if username and password:
                    connection = pki.server.PKIServer.setup_password_authentication(
                        username, password, subsystem_name='ca', secure_port=secure_port,
                        client_nssdb=client_nssdb)
                else:
                    if not client_cert:
                        raise pki.server.PKIServerException('Client cert nick name required.')
                    if not client_nssdb_pass and not client_nssdb_pass_file:
                        raise pki.server.PKIServerException('NSS db password required.')
                    connection = pki.server.PKIServer.setup_cert_authentication(
                        client_nssdb_pass=client_nssdb_pass,
                        client_cert=client_cert,
                        client_nssdb_pass_file=client_nssdb_pass_file,
                        client_nssdb=client_nssdb,
                        tmpdir=tmpdir,
                        secure_port=secure_port
                    )

                pki.server.PKIServer.renew_certificate(connection, new_cert_file, serial)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def verify_cert(self, cert_data):

        nssdb = self.open_nssdb()

        try:
            nssdb.verify_cert(cert_data=cert_data)

        finally:
            nssdb.close()

    def init(self):
        super().init()
        self.validate_banner()

    @classmethod
    def instances(cls):

        instances = []

        if not os.path.exists(pki.server.PKIServer.BASE_DIR):
            return instances

        for instance_name in os.listdir(pki.server.PKIServer.BASE_DIR):
            instance_dir = os.path.join(pki.server.PKIServer.BASE_DIR, instance_name)
            if not os.path.isdir(instance_dir):
                continue
            instance = PKIInstance(instance_name)
            instance.load()
            instances.append(instance)

        return instances
