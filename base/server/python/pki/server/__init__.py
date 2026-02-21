# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#     Marco Fargetta <mfargett@redhat.com>
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

import datetime
import functools
import getpass
import grp
import inspect
import logging
import os
import pathlib
import pwd
import re
import requests
import selinux
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import ldap
import ldap.filter
import pki
import pki.account
import pki.cert
import pki.client
import pki.nssdb
import pki.util
from pki.keyring import Keyring
import pki.server.subsystem

seobject = None
if selinux.is_selinux_enabled():
    try:
        import seobject
    except ImportError:
        # TODO: Fedora 22 has an incomplete Python 3 package
        # sepolgen is missing.
        if sys.version_info.major == 2:
            raise

SYSCONFIG_DIR = '/etc/sysconfig'
ETC_SYSTEMD_DIR = '/etc/systemd'
LIB_SYSTEMD_DIR = '/lib/systemd'
FAPOLICY_RULES_PATH = '/etc/fapolicyd/rules.d'


SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps', 'acme', 'est']

DEFAULT_DIR_MODE = 0o0770
DEFAULT_FILE_MODE = 0o0660
DEFAULT_LINK_MODE = 0o0777

SCHEMA_FILES = [
    '/usr/share/pki/server/database/ds/schema.ldif'
]

DEFAULT_INSTANCE_NAME = 'pki-quarkus'

DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTPS_PORT = 8443

PKI_INSTANCE_SELINUX_CONTEXT = 'pki_tomcat_var_lib_t'
PKI_LOG_SELINUX_CONTEXT = 'pki_tomcat_log_t'
PKI_CFG_SELINUX_CONTEXT = 'pki_tomcat_etc_rw_t'
PKI_CERTDB_SELINUX_CONTEXT = 'pki_tomcat_cert_t'
PKI_PORT_SELINUX_CONTEXT = 'http_port_t'

logger = logging.getLogger(__name__)


@functools.total_ordering
class PKIServer(object):

    BASE_DIR = '/var/lib/pki'
    CONFIG_DIR = '/etc/pki'
    LOG_DIR = '/var/log/pki'
    SHARE_DIR = '/usr/share/pki'
    JAVA_DIR = '/usr/share/java'
    REGISTRY_DIR = SYSCONFIG_DIR + '/pki'

    def __init__(self,
                 name,
                 instance_type='pki-quarkusd',
                 user='pkiuser',
                 group='pkiuser'):

        self.name = name
        self.type = instance_type
        self.user = user
        self.group = group

        # The standard conf dir at /var/lib/pki/<instance>/conf
        # will be an actual folder (i.e. not a link).
        self._conf_dir = None

        # The standard logs dir at /var/lib/pki/<instance>/logs
        # will be an actual folder (i.e. not a link).
        self._logs_dir = None

        self.config = {}
        self.passwords = {}
        self.subsystems = {}

    def __repr__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, PKIServer):
            return NotImplemented
        return self.name == other.name

    def __lt__(self, other):
        if not isinstance(other, PKIServer):
            return NotImplemented
        return self.name < other.name

    @property
    def base_dir(self):
        return os.path.join(PKIServer.BASE_DIR, self.name)

    @property
    def conf_dir(self):
        return os.path.join(self.base_dir, 'conf')

    @property
    def actual_conf_dir(self):
        return self._conf_dir if self._conf_dir else self.conf_dir

    @actual_conf_dir.setter
    def actual_conf_dir(self, value):
        self._conf_dir = value

    @property
    def certs_dir(self):
        return os.path.join(self.conf_dir, 'certs')

    @property
    def lib_dir(self):
        return os.path.join(self.base_dir, 'lib')

    @property
    def common_dir(self):
        return os.path.join(self.base_dir, 'common')

    @property
    def common_lib_dir(self):
        return os.path.join(self.common_dir, 'lib')

    @property
    def logs_dir(self):
        return os.path.join(self.base_dir, 'logs')

    @property
    def actual_logs_dir(self):
        return self._logs_dir if self._logs_dir else self.logs_dir

    @actual_logs_dir.setter
    def actual_logs_dir(self, value):
        self._logs_dir = value

    @property
    def service_name(self):
        return '%s@%s' % (self.type, self.name)

    @property
    def service_conf(self):
        return os.path.join(SYSCONFIG_DIR, self.service_name)

    @property
    def uid(self):
        return pwd.getpwnam(self.user).pw_uid

    @property
    def gid(self):
        return grp.getgrnam(self.group).gr_gid

    @property
    def password_conf(self):
        return os.path.join(self.conf_dir, 'password.conf')

    @property
    def nssdb_dir(self):
        return os.path.join(self.conf_dir, 'alias')

    @property
    def nssdb_link(self):
        return os.path.join(self.base_dir, 'alias')

    @property
    def jss_conf(self):
        return os.path.join(self.conf_dir, 'jss.conf')

    @property
    def fapolicy_rule_file(self):
        return os.path.join(FAPOLICY_RULES_PATH, '61-pki-{}.rules'.format(self.name))

    @property
    def ca_cert(self):
        return os.path.join(self.nssdb_dir, 'ca.crt')

    def is_valid(self):
        return self.exists()

    def exists(self):
        '''
        Check whether the PKI server instance exists.

        This method checks the conf folder under the instance's base folder.
        If the folder exists the method will return True, otherwise False.

        The instance's base folder itself is not a reliable indicator since
        there might be files (e.g. config files, logs) left in the folder
        after removing an instance.
        '''
        return os.path.isdir(self.conf_dir)

    def validate(self):
        if not self.exists():
            raise pki.PKIException('Invalid instance: ' + self.name, None)

    def is_active(self):
        cmd = ['systemctl', '--quiet', 'is-active', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        rc = subprocess.call(cmd)
        return rc == 0

    def cert_file(self, cert_id):
        '''
        Compute name of certificate under instance certs folder.
        '''
        return os.path.join(self.certs_dir, cert_id + '.crt')

    def csr_file(self, cert_id):
        '''
        Compute name of CSR under instance certs folder.
        '''
        return os.path.join(self.certs_dir, cert_id + '.csr')

    def init(self):

        if os.environ.get('PKI_SERVER_AUTO_ENABLE_SUBSYSTEMS', 'true') == 'true':
            self.enable_subsystems()

    def start(self, wait=False, max_wait=60, timeout=None):

        cmd = ['systemctl', 'start', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def stop(self, wait=False, max_wait=60, timeout=None):

        cmd = ['systemctl', 'stop', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def restart(self, wait=False, max_wait=60, timeout=None):
        self.stop(wait=True, max_wait=max_wait, timeout=timeout)
        self.start(wait=wait, max_wait=max_wait, timeout=timeout)

    def enable(self):
        cmd = ['systemctl', 'enable', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def disable(self):
        cmd = ['systemctl', 'disable', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def chown(self, path):

        if not os.geteuid() == 0:
            return

        pki.util.chown(path, self.uid, self.gid)

    def touch(self, path):
        pathlib.Path(path).touch()
        self.chown(path)
        os.chmod(path, DEFAULT_FILE_MODE)

    def makedirs(self, path, exist_ok=None, force=False):

        if os.path.isdir(path) and exist_ok:
            logger.info('Reusing %s', path)
            return

        logger.info('Creating %s', path)

        pki.util.makedirs(
            path,
            mode=DEFAULT_DIR_MODE,
            exist_ok=exist_ok,
            uid=self.uid,
            gid=self.gid,
            force=force)

    def symlink(self, source, dest, exist_ok=False):

        if os.path.islink(dest) and exist_ok:
            logger.info('Reusing %s', dest)
            return

        logger.info('Linking %s to %s', dest, source)

        pki.util.symlink(
            source,
            dest,
            uid=self.uid,
            gid=self.gid,
            exist_ok=exist_ok)

    def copy(self, source, dest, exist_ok=False, force=False):

        if os.path.exists(dest) and exist_ok:
            logger.info('Reusing %s', dest)
            return

        logger.info('Copying %s to %s', source, dest)

        pki.util.copy(
            source,
            dest,
            uid=self.uid,
            gid=self.gid,
            dir_mode=DEFAULT_DIR_MODE,
            file_mode=DEFAULT_FILE_MODE,
            force=force)

    def copydirs(self, source, dest, force=False):

        logger.info('Creating %s', dest)

        pki.util.copydirs(
            source,
            dest,
            uid=self.uid,
            gid=self.gid,
            mode=DEFAULT_DIR_MODE,
            force=force)

    def copyfile(self, source, dest, params=None, exist_ok=False, force=False):

        if os.path.exists(dest) and exist_ok:
            logger.info('Reusing %s', dest)
            return

        logger.info('Creating %s', dest)

        pki.util.copyfile(
            source,
            dest,
            params=params,
            uid=self.uid,
            gid=self.gid,
            mode=DEFAULT_FILE_MODE,
            force=force)

    def store_properties(self, filename, properties):
        pki.util.store_properties(filename, properties)
        os.chmod(filename, DEFAULT_FILE_MODE)
        self.chown(filename)

    def create(self, force=False):

        self.makedirs(self.base_dir, exist_ok=True)

        self.create_conf_dir(exist_ok=True)
        self.create_logs_dir(exist_ok=True)
        self.create_libs(force=force)

        self.makedirs(self.certs_dir, exist_ok=True)

    def create_conf_dir(self, exist_ok=False):

        if self._conf_dir:

            # Create /etc/pki/<instance>
            self.makedirs(self._conf_dir, exist_ok=exist_ok)

            # Link /var/lib/pki/<instance>/conf to /etc/pki/<instance>
            self.symlink(self._conf_dir, self.conf_dir, exist_ok=exist_ok)

            return

        # Create /var/lib/pki/<instance>/conf
        self.makedirs(self.conf_dir, exist_ok=exist_ok)

    def create_logs_dir(self, exist_ok=False):

        if self._logs_dir:

            # Create /var/log/pki/<instance>
            self.makedirs(self._logs_dir, exist_ok=exist_ok)

            # Create /var/log/pki/<instance>/backup
            backup_dir = os.path.join(self._logs_dir, 'backup')
            self.makedirs(backup_dir, exist_ok=exist_ok)

            # Link /var/lib/pki/<instance>/logs to /var/log/pki/<instance>
            self.symlink(self._logs_dir, self.logs_dir, exist_ok=exist_ok)

            return

        # Create /var/lib/pki/<instance>/logs
        self.makedirs(self.logs_dir, exist_ok=exist_ok)

        # Create /var/lib/pki/<instance>/logs/backup
        backup_dir = os.path.join(self.logs_dir, 'backup')
        self.makedirs(backup_dir, exist_ok=exist_ok)

    def create_libs(self, force=False):  # pylint: disable=W0613

        lib_dir = os.path.join(PKIServer.SHARE_DIR, 'server', 'lib')
        self.symlink(lib_dir, self.lib_dir, exist_ok=True)

        self.makedirs(self.common_dir, exist_ok=True)

        common_lib_dir = os.path.join(PKIServer.SHARE_DIR, 'server', 'common', 'lib')
        self.symlink(common_lib_dir, self.common_lib_dir, exist_ok=True)

    def create_nssdb(self, force=False):

        logger.info('Creating %s', self.nssdb_dir)

        if force and os.path.exists(self.nssdb_dir):
            logger.warning('NSS database already exists: %s', self.nssdb_dir)
            return

        self.makedirs(self.nssdb_dir, exist_ok=True)

        self.symlink(self.nssdb_dir, self.nssdb_link, exist_ok=True)

        password = self.passwords.get(pki.nssdb.INTERNAL_TOKEN_NAME)

        nssdb = pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            password=password)

        try:
            nssdb.create()
        finally:
            nssdb.close()

        self.chown(self.nssdb_dir)

    def open_nssdb(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):
        return pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            token=token,
            password=self.get_token_password(token),
            internal_password=self.get_token_password(),
            passwords=self.passwords,
            password_conf=self.password_conf,
            user=self.user,
            group=self.group)

    def remove(self, remove_conf=False, remove_logs=False, force=False):

        logger.info('Removing %s', self.service_conf)
        pki.util.remove(self.service_conf, force=force)

        if remove_logs:
            self.remove_logs_dir(force=force)

        self.remove_libs(force=force)

        if remove_conf:
            self.remove_conf_dir(force=force)

        # remove <instance base dir>/alias if exists
        if os.path.islink(self.nssdb_link):
            logger.info('Removing %s', self.nssdb_link)
            pki.util.unlink(self.nssdb_link)

        if os.path.isdir(self.base_dir) and not os.listdir(self.base_dir):

            # Remove <instance base dir> if empty
            logger.info('Removing %s', self.base_dir)
            pki.util.rmtree(self.base_dir, force=force)

    def remove_libs(self, force=False):

        logger.info('Removing %s', self.common_lib_dir)
        pki.util.unlink(self.common_lib_dir, force=force)

        logger.info('Removing %s', self.common_dir)
        pki.util.rmtree(self.common_dir, force=force)

        logger.info('Removing %s', self.lib_dir)
        pki.util.unlink(self.lib_dir, force=force)

    def remove_logs_dir(self, force=False):

        if os.path.islink(self.logs_dir):

            # Get the actual folder in case it has changed
            _logs_dir = os.readlink(self.logs_dir)

            # Remove /var/lib/pki/<instance>/logs
            logger.info('Removing %s', self.logs_dir)
            pki.util.unlink(self.logs_dir, force=force)

            # Remove /var/log/pki/<instance>
            logger.info('Removing %s', _logs_dir)
            pki.util.rmtree(_logs_dir, force=force)

            return

        # Remove /var/lib/pki/<instance>/logs
        logger.info('Removing %s', self.logs_dir)
        pki.util.rmtree(self.logs_dir, force=force)

    def remove_conf_dir(self, force=False):

        if os.path.islink(self.conf_dir):

            # Get the actual folder in case it has changed
            _conf_dir = os.readlink(self.conf_dir)

            # Remove /var/lib/pki/<instance>/conf
            logger.info('Removing %s', self.conf_dir)
            pki.util.unlink(self.conf_dir, force=force)

            # Remove /etc/pki/<instance>
            logger.info('Removing %s', _conf_dir)
            pki.util.rmtree(_conf_dir, force=force)

            return

        # Remove /var/lib/pki/<instance>/conf
        logger.info('Removing %s', self.conf_dir)
        pki.util.rmtree(self.conf_dir, force=force)

    def remove_nssdb(self, force=False):

        logger.info('Removing %s', self.nssdb_link)
        pki.util.unlink(self.nssdb_link, force=force)

        logger.info('Removing %s', self.nssdb_dir)
        pki.util.rmtree(self.nssdb_dir, force=force)

    def load(self):

        logger.info('Loading instance: %s', self.name)

        self.load_config()
        self.load_passwords()
        self.load_subsystems()

    def load_config(self):

        self.config.clear()

        # Load PKI config
        pki_conf = os.path.join(PKIServer.SHARE_DIR, 'etc', 'pki.conf')
        if os.path.exists(pki_conf):
            logger.info('Loading PKI config: %s', pki_conf)
            pki.util.load_properties(pki_conf, self.config)

        # Load instance sysconfig
        if os.path.exists(self.service_conf):
            logger.info('Loading instance config: %s', self.service_conf)
            pki.util.load_properties(self.service_conf, self.config)

        # strip quotes
        for name, value in self.config.items():
            if value.startswith('"') and value.endswith('"'):
                self.config[name] = value[1:-1]

        self.config['NAME'] = self.name

    def load_passwords(self):

        self.passwords.clear()

        if os.path.exists(self.password_conf):
            logger.info('Loading password config: %s', self.password_conf)
            pki.util.load_properties(self.password_conf, self.passwords)

    def store_passwords(self):

        if os.path.exists(self.password_conf):
            logger.info('Updating %s', self.password_conf)
        else:
            logger.info('Creating %s', self.password_conf)

        self.store_properties(self.password_conf, self.passwords)

    def remove_passwords(self, force=False):
        logger.info('Removing %s', self.password_conf)
        pki.util.remove(self.password_conf, force=force)

    def store_cert_request(self, cert_id, cert):

        self.makedirs(self.certs_dir, exist_ok=True)

        csr_data = cert.get('request')
        csr_pem = pki.nssdb.convert_csr(csr_data, 'base64', 'pem')

        csr_file = self.csr_file(cert_id)
        with open(csr_file, 'w', encoding='utf-8') as f:
            f.write(csr_pem)

        self.chown(csr_file)

    def load_subsystems(self):

        for subsystem_name in SUBSYSTEM_TYPES:

            subsystem_dir = os.path.join(self.base_dir, subsystem_name)

            # ensure /var/lib/pki/<instance>/<subsystem> exists
            if not os.path.exists(subsystem_dir):
                continue

            # ensure /var/lib/pki/<instance>/<subsystem> is not empty
            # https://issues.redhat.com/browse/RHEL-21568
            if not os.listdir(subsystem_dir):
                # Directory exists but it is empty
                continue

            subsystem = pki.server.subsystem.PKISubsystemFactory.create(self, subsystem_name)
            subsystem.load()

            self.add_subsystem(subsystem)

    def get_subsystems(self):
        return list(self.subsystems.values())

    def get_subsystem(self, subsystem_name):
        return self.subsystems.get(subsystem_name)

    def add_subsystem(self, subsystem):
        self.subsystems[subsystem.name] = subsystem

    def remove_subsystem(self, subsystem_name):
        return self.subsystems.pop(subsystem_name, None)

    def enable_subsystems(self):
        for subsystem in self.get_subsystems():
            if not subsystem.is_enabled():
                subsystem.enable()

    def load_jss_config(self):

        jss_config = {}

        if os.path.exists(self.jss_conf):
            logger.info('Loading JSS config: %s', self.jss_conf)
            pki.util.load_properties(self.jss_conf, jss_config)

        return jss_config

    def store_jss_config(self, jss_config):
        self.store_properties(self.jss_conf, jss_config)

    def get_password(self, name):

        # find password (e.g. internaldb, replicationdb) in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # find password in keyring
        try:
            keyring = Keyring()
            key_name = self.name + '/' + name
            password = keyring.get_password(key_name=key_name)
            self.passwords[name] = password
            return password

        except (subprocess.CalledProcessError, ValueError) as e:
            logger.debug('Password unavailable in Keyring: %s', e)

        try:
            # prompt for password if not found and terminal is available
            password = getpass.getpass(prompt='Enter password for %s: ' % name)
            self.passwords[name] = password
            return password
        except EOFError:
            logger.info('Password cannot be provided from standard I/O')

        raise Exception('No available password for "%s"' % name)

    def get_token_password(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):

        # determine the password name for the token
        if pki.nssdb.internal_token(token):
            name = pki.nssdb.INTERNAL_TOKEN_NAME

        else:
            name = 'hardware-%s' % token

        # find password in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # find password in keyring
        try:
            keyring = Keyring()
            key_name = self.name + '/' + name
            password = keyring.get_password(key_name=key_name)
            self.passwords[name] = password
            return password

        except (subprocess.CalledProcessError, ValueError) as e:
            logger.debug('Password unavailable in Keyring: %s', e)

        try:
            # prompt for password if not found and terminal is available
            password = getpass.getpass(prompt='Enter password for %s: ' % token)
            self.passwords[name] = password
            return password
        except EOFError:
            logger.info('Password cannot be provided from standard I/O')

        raise Exception('No available password to access the token "%s"' % token)

    def selinux_context_exists(self, records, context_value):
        '''
        Check if a given `context_value` exists in the given set of `records`.
        This method can process both port contexts and file contexts.
        '''
        for keys in records.keys():
            for key in keys:
                if str(key) == context_value:
                    return True
        return False

    def create_selinux_contexts(self, ports):

        suffix = '(/.*)?'

        trans = seobject.semanageRecords('targeted')
        trans.start()

        fcon = seobject.fcontextRecords(trans)

        logger.info('Adding SELinux fcontext "%s"', self.actual_conf_dir + suffix)
        fcon.add(
            self.actual_conf_dir + suffix,
            pki.server.PKI_CFG_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.nssdb_dir + suffix)
        fcon.add(
            self.nssdb_dir + suffix,
            pki.server.PKI_CERTDB_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.base_dir + suffix)
        fcon.add(
            self.base_dir + suffix,
            pki.server.PKI_INSTANCE_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.actual_logs_dir + suffix)
        fcon.add(
            self.actual_logs_dir + suffix,
            pki.server.PKI_LOG_SELINUX_CONTEXT, '', 's0', '')

        port_records = seobject.portRecords(trans)

        for port in ports:
            logger.info('Adding SELinux port %s', port)
            port_records.add(
                port, 'tcp', 's0',
                pki.server.PKI_PORT_SELINUX_CONTEXT)

        trans.finish()

    def remove_selinux_contexts(self, ports):

        suffix = '(/.*)?'

        trans = seobject.semanageRecords('targeted')
        trans.start()

        port_records = seobject.portRecords(trans)
        port_record_values = port_records.get_all()

        for port in ports:
            if self.selinux_context_exists(port_record_values, port):
                logger.info('Removing SELinux port %s', port)
                port_records.delete(port, 'tcp')

        fcon = seobject.fcontextRecords(trans)
        file_records = fcon.get_all()

        if self.selinux_context_exists(file_records, self.actual_logs_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.actual_logs_dir + suffix)
            fcon.delete(self.actual_logs_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.base_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.base_dir + suffix)
            fcon.delete(self.base_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.nssdb_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.nssdb_dir + suffix)
            fcon.delete(self.nssdb_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.actual_conf_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.actual_conf_dir + suffix)
            fcon.delete(self.actual_conf_dir + suffix, '')

        trans.finish()

    def restore_selinux_contexts(self):
        '''
        The restocon API is not working in RHEL
        (see https://issues.redhat.com/browse/RHEL-73348).

        selinux.restorecon(self.base_dir, True)
        selinux.restorecon(PKIServer.LOG_DIR, True)
        selinux.restorecon(self.actual_logs_dir, True)
        selinux.restorecon(self.actual_conf_dir, True)
        '''

        folders = [
            self.base_dir,
            PKIServer.LOG_DIR,
            self.actual_logs_dir,
            self.actual_conf_dir
        ]

        for folder in folders:

            cmd = [
                '/usr/sbin/restorecon',
                '-R'
            ]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('-v')

            cmd.append(folder)

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.run(cmd, check=True)

    def restart_fapolicy_daemon(self):
        '''
        Helper function to restart the fapolicyd after the rules are updated.
        '''

        cmd = ['systemctl', 'is-active', '--quiet', 'fapolicyd']

        logger.debug('Command: %s', ' '.join(cmd))
        stat = subprocess.call(cmd)

        if stat != 0:
            return

        logger.info('Restarting fapolicy daemon')

        cmd = ['systemctl', 'restart', '--quiet', 'fapolicyd']

        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.call(cmd)

    def install_fapolicy_rules(self):

        logger.info('Installing fapolicy rules')

        if not os.path.exists(FAPOLICY_RULES_PATH):
            # fapolicy folder not found
            return

        template = os.path.join(
            PKIServer.SHARE_DIR,
            'server',
            'etc',
            'fapolicy.rules')

        params = {
            'WORK_DIR': self.work_dir
        }

        uid = pwd.getpwnam('root').pw_uid
        gid = grp.getgrnam('fapolicyd').gr_gid
        mode = 0o644

        logger.info('Creating %s', self.fapolicy_rule_file)
        pki.util.copyfile(
            template,
            self.fapolicy_rule_file,
            params=params,
            uid=uid,
            gid=gid,
            mode=mode,
            force=True)

        self.restart_fapolicy_daemon()

    def remove_fapolicy_rules(self):

        logger.info('Removing fapolicy rules')

        if not os.path.exists(self.fapolicy_rule_file):
            # rules not found
            return

        logger.info('Removing %s', self.fapolicy_rule_file)
        os.remove(self.fapolicy_rule_file)

        self.restart_fapolicy_daemon()

    @staticmethod
    def split_cert_id(cert_id):
        """
        Utility method to return cert_tag and corresponding subsystem details from cert_id

        :param cert_id: Cert ID
        :type cert_id: str
        :returns: (subsystem_name, cert_tag)
        :rtype: (str, str)
        """
        if cert_id == 'sslserver' or cert_id == 'subsystem':
            subsystem_name = None
            cert_tag = cert_id
        else:
            parts = cert_id.split('_', 1)
            subsystem_name = parts[0]
            cert_tag = parts[1]
        return subsystem_name, cert_tag

    @staticmethod
    def build_ca_files(client_nssdb):
        if not client_nssdb:
            return None

        ca_cert = os.path.join(client_nssdb, "ca.crt")
        if os.path.exists(ca_cert):
            return ca_cert

        return None

    @staticmethod
    def setup_password_authentication(username, password, subsystem_name='ca', secure_port='8443',
                                      client_nssdb=None):
        """
        Return a PKIConnection, logged in using username and password.
        """
        ca_cert = PKIServer.build_ca_files(client_nssdb)
        connection = pki.client.PKIConnection('https', socket.getfqdn(), secure_port,
                                              cert_paths=ca_cert)
        connection.authenticate(username, password)
        account_client = pki.account.AccountClient(connection, subsystem=subsystem_name)
        account_client.login()
        return connection

    @staticmethod
    def setup_cert_authentication(
            client_nssdb_pass, client_nssdb_pass_file, client_cert,
            client_nssdb, tmpdir, subsystem_name=None, secure_port='8443'):
        """
        Utility method to set up a secure authenticated connection with a
        subsystem of PKI Server through PKI client

        :param client_nssdb_pass: Client NSS db plain password
        :type client_nssdb_pass: str
        :param client_nssdb_pass_file: File containing client NSS db password
        :type client_nssdb_pass_file: str
        :param client_cert: Client Cert nick name
        :type client_cert: str
        :param client_nssdb: Client NSS db path
        :type client_nssdb: str
        :param tmpdir: Absolute path of temp dir to store p12 and pem files
        :type tmpdir: str
        :param subsystem_name: Name of the subsystem
           DEPRECATED: https://github.com/dogtagpki/pki/wiki/PKI-10.8-Python-Changes
        :type subsystem_name: str
        :param secure_port: Secure Port Number
        :type secure_port: str
        :return: Authenticated secure connection to PKI server
        """

        if subsystem_name is not None:
            logger.warning(
                '%s:%s: The subsystem_name in PKIServer.setup_cert_authentication() has '
                'been deprecated (https://github.com/dogtagpki/pki/wiki/PKI-10.8-Python-Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

        temp_auth_p12 = os.path.join(tmpdir, 'auth.p12')
        temp_auth_cert = os.path.join(tmpdir, 'auth.pem')

        if not client_cert:
            raise PKIServerException('Client cert nickname is required.')

        # Create a p12 file using
        # pk12util -o <p12 file name> -n <cert nick name> -d <NSS db path>
        # -W <pkcs12 password> -K <NSS db pass>
        cmd_generate_pk12 = [
            'pk12util',
            '-o', temp_auth_p12,
            '-n', client_cert,
            '-d', client_nssdb
        ]

        # The pem file used for authentication. Created from a p12 file using the
        # command:
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
        cmd_generate_pem = [
            'openssl',
            'pkcs12',
            '-in', temp_auth_p12,
            '-out', temp_auth_cert,
            '-nodes'
        ]

        # The PEM file containing the CA certificate. Created from a p12 file
        # using the command:
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes -cacerts -nokeys
        cmd_generate_ca = [
            'openssl', 'pkcs12',
            '-in', temp_auth_p12,
            '-out', os.path.join(client_nssdb, "ca.crt"),
            '-nodes',
            '-cacerts',
            '-nokeys'
        ]

        if client_nssdb_pass_file:
            # Use the same password file for the generated pk12 file
            cmd_generate_pk12.extend(['-k', client_nssdb_pass_file,
                                      '-w', client_nssdb_pass_file])
            cmd_generate_pem.extend(['-passin', 'file:' + client_nssdb_pass_file])
            cmd_generate_ca.extend(['-passin', 'file:' + client_nssdb_pass_file])
        else:
            # Use the same password for the generated pk12 file
            cmd_generate_pk12.extend(['-K', client_nssdb_pass,
                                      '-W', client_nssdb_pass])
            cmd_generate_pem.extend(['-passin', 'pass:' + client_nssdb_pass])
            cmd_generate_ca.extend(['-passin', 'pass:' + client_nssdb_pass])

        # Generate temp_auth_p12 file
        logger.debug('Command: %s', ' '.join(cmd_generate_pk12))
        res_pk12 = subprocess.check_output(cmd_generate_pk12,
                                           stderr=subprocess.STDOUT).decode('utf-8')
        logger.debug('Result of pk12 generation: %s', res_pk12)

        # Use temp_auth_p12 generated in previous step to
        # to generate temp_auth_cert PEM file
        logger.debug('Command: %s', ' '.join(cmd_generate_pem))
        res_pem = subprocess.check_output(cmd_generate_pem,
                                          stderr=subprocess.STDOUT).decode('utf-8')
        logger.debug('Result of pem generation: %s', res_pem)

        # When we generate the .p12 file, we can extract the ca certificate.
        # We remove it when it already exists. This ensures we always have
        # an up-to-date CA certificate.
        ca_cert = PKIServer.build_ca_files(client_nssdb)
        if ca_cert and os.path.exists(ca_cert):
            os.remove(ca_cert)

        # Export the CA each time. This ensures it is always up to date when
        # trying to connect.
        logger.debug('Command: %s', ' '.join(cmd_generate_ca))
        res_ca = subprocess.check_output(cmd_generate_ca,
                                         stderr=subprocess.STDOUT).decode('utf-8')
        logger.debug('Result of CA generation: %s', res_ca)
        ca_cert = PKIServer.build_ca_files(client_nssdb)

        # Create a PKIConnection object that stores the details of subsystem.
        connection = pki.client.PKIConnection('https', socket.getfqdn(), secure_port,
                                              subsystem_name, cert_paths=ca_cert)

        # Bind the authentication with the connection object
        connection.set_authentication_cert(temp_auth_cert)

        return connection

    @staticmethod
    def renew_certificate(connection, output, serial):
        """
        Renew cert associated with the provided serial

        :param connection: Secure authenticated connection to PKI Server
        :type connection: PKIConnection
        :param output: Location of the new cert file to be written to
        :type output: str
        :param serial: Serial number of the cert to be renewed
        :type serial: str
        :return: None
        :rtype: None
        """

        logger.info('Renewing cert %s', hex(int(serial)))

        # Instantiate the CertClient
        cert_client = pki.cert.CertClient(connection)

        inputs = dict()
        inputs['serial_num'] = serial

        # request: CertRequestInfo object for request generated.
        # cert: CertData object for certificate generated (if any)
        ret = cert_client.enroll_cert(inputs=inputs, profile_id='caManualRenewal')

        request_data = ret[0].request
        cert_data = ret[0].cert

        logger.info('- request ID: %s', hex(int(request_data.request_id)))
        logger.info('- request status: %s', request_data.request_status)
        logger.debug('- request data: %s', request_data)
        logger.debug('- cert data: %s', cert_data)

        if not cert_data:
            raise PKIServerException('Unable to renew certificate %s' % hex(int(serial)))

        # store cert_id for usage later
        cert_serial_number = cert_data.serial_number
        if not cert_serial_number:
            raise PKIServerException('Unable to retrieve serial number of '
                                     'renewed certificate.')

        logger.info('- serial number: %s', cert_serial_number)
        logger.info('- issuer: %s', cert_data.issuer_dn)
        logger.info('- subject: %s', cert_data.subject_dn)
        logger.debug(cert_data.pretty_repr)

        new_cert_data = cert_client.get_cert(cert_serial_number=cert_serial_number)

        logger.info('Storing cert into %s', output)
        with open(output, 'w', encoding='utf-8') as f:
            f.write(new_cert_data.encoded)

    @staticmethod
    def load_audit_events(filename):
        '''
        This method loads audit event info from audit-events.properties
        and return it as a map of objects.
        '''

        logger.info('Loading %s', filename)

        with open(filename, encoding='utf-8') as f:
            lines = f.read().splitlines()

        events = {}

        event_pattern = re.compile(r'# Event: (\S+)')
        subsystems_pattern = re.compile(r'# Applicable subsystems: (.*)')
        enabled_pattern = re.compile(r'# Enabled by default: (.*)')

        event = None

        for line in lines:

            logger.debug('Parsing: %s', line)

            event_match = event_pattern.match(line)
            if event_match:

                name = event_match.group(1)
                logger.info('Found event %s', name)

                event = {}
                event['name'] = name
                event['subsystems'] = []
                event['enabled_by_default'] = False

                events[name] = event
                continue

            subsystems_match = subsystems_pattern.match(line)
            if subsystems_match:

                subsystems = subsystems_match.group(1)
                logger.info('Found subsystems %s', subsystems)

                subsystems = subsystems.replace(' ', '').split(',')
                event['subsystems'] = subsystems

            enabled_match = enabled_pattern.match(line)
            if enabled_match:

                enabled = enabled_match.group(1)
                logger.info('Found enabled by default %s', enabled)

                if enabled == 'Yes':
                    event['enabled_by_default'] = True
                else:
                    event['enabled_by_default'] = False

        logger.info('Events:')

        for name, event in events.items():
            logger.info('- %s', name)
            logger.info('  Applicable subsystems: %s', event['subsystems'])
            logger.info('  Enabled by default: %s', event['enabled_by_default'])

        return events


class ExternalCert(object):

    def __init__(self, nickname=None, token=None):
        self.nickname = nickname
        self.token = token


class PKIDatabaseConnection(object):

    def __init__(self, url='ldap://localhost:389'):

        self.url = url

        self.nssdb_dir = None

        self.bind_dn = None
        self.bind_password = None

        self.client_cert_nickname = None
        self.nssdb_password = None

        self.temp_dir = None
        self.ldap = None

    def set_security_database(self, nssdb_dir=None):
        self.nssdb_dir = nssdb_dir

    def set_credentials(self, bind_dn=None, bind_password=None,
                        client_cert_nickname=None, nssdb_password=None):
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.client_cert_nickname = client_cert_nickname
        self.nssdb_password = nssdb_password

    def open(self):

        self.temp_dir = tempfile.mkdtemp()

        if self.nssdb_dir:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, self.nssdb_dir)

        if self.client_cert_nickname:
            password_file = os.path.join(self.temp_dir, 'password.txt')
            with open(password_file, 'w', encoding='utf-8') as f:
                f.write(self.nssdb_password)

            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, self.client_cert_nickname)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, password_file)

        self.ldap = ldap.initialize(self.url)

        if self.bind_dn and self.bind_password:
            self.ldap.simple_bind_s(self.bind_dn, self.bind_password)

    def close(self):

        if self.ldap:
            self.ldap.unbind_s()

        if self.temp_dir:
            shutil.rmtree(self.temp_dir)


class PKIServerException(pki.PKIException):

    def __init__(self, message, exception=None,
                 instance=None, subsystem=None):
        pki.PKIException.__init__(self, message, exception)

        self.instance = instance
        self.subsystem = subsystem


class PKIServerFactory(object):

    @classmethod
    def create(cls, name):
        '''
        This method creates PKIServer object based on the
        optional service type specified in the service name.
        The default type is 'pki-quarkusd'.

        :param name: Server name in this format: [<type>@]<name>[.service]
        '''

        if name.endswith('.service'):
            name = name[0:-8]

        parts = name.split('@')

        if len(parts) == 1:  # no type
            instance_type = 'pki-quarkusd'
            instance_name = name

        else:  # with type
            instance_type = parts[0]
            instance_name = parts[1]

        logger.info('Loading instance type: %s', instance_type)

        if instance_type.startswith('pki-quarkusd'):
            module = __import__('pki.server.instance', fromlist=['PKIInstance'])
            clazz = getattr(module, 'PKIInstance')
            return clazz(instance_name, instance_type=instance_type)

        raise Exception('Unsupported instance type: %s' % instance_type)
