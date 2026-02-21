# Authors:
#     Claude Code Migration Tool
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
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#

"""
Quarkus PKI Instance Management

This module provides classes and utilities for managing Dogtag PKI subsystems
deployed as Quarkus applications instead of Tomcat webapps.

Key differences from Tomcat deployment:
  - Each subsystem runs as an independent process (no shared JVM)
  - Configuration uses application.yaml instead of CS.cfg + web.xml
  - No Catalina/localhost XML context files
  - systemd service template: pki-quarkusd@.service
  - Quarkus runner JAR instead of WAR deployment
"""

from __future__ import absolute_import

import logging
import os
import subprocess

import pki
import pki.server

logger = logging.getLogger(__name__)


# Subsystem types that have Quarkus modules
QUARKUS_SUBSYSTEMS = ['ca', 'kra', 'ocsp', 'tks', 'tps', 'acme', 'est']


class QuarkusPKIInstance:
    """
    Manages a Quarkus-based PKI subsystem instance.

    Unlike Tomcat-based instances where multiple subsystems share a single
    Tomcat process, each Quarkus subsystem runs as an independent process
    using the Quarkus runner JAR.

    Directory layout:
        /var/lib/pki/<instance>/          - base directory
        /var/lib/pki/<instance>/conf/     - configuration (CS.cfg, application.yaml)
        /var/lib/pki/<instance>/logs/     - log files
        /var/lib/pki/<instance>/alias/    - NSS database
        /etc/pki/<instance>/              - actual config directory (linked)
        /var/log/pki/<instance>/          - actual log directory (linked)
    """

    BASE_DIR = '/var/lib/pki'
    CONFIG_DIR = '/etc/pki'
    LOG_DIR = '/var/log/pki'
    SHARE_DIR = '/usr/share/pki'
    LIB_SYSTEMD_DIR = '/usr/lib/systemd'
    ETC_SYSTEMD_DIR = '/etc/systemd'

    UNIT_FILE = LIB_SYSTEMD_DIR + '/system/pki-quarkusd@.service'
    TARGET_FILE = LIB_SYSTEMD_DIR + '/system/pki-quarkusd.target'
    TARGET_WANTS = ETC_SYSTEMD_DIR + '/system/pki-quarkusd.target.wants'

    def __init__(self, name, subsystem_type, user='pkiuser', group='pkiuser'):
        """
        Initialize a Quarkus PKI instance.

        Args:
            name: Instance name (e.g., 'pki-quarkus')
            subsystem_type: Subsystem type (ca, kra, ocsp, tks, tps, acme, est)
            user: System user to run as
            group: System group to run as
        """
        self.name = name
        self.subsystem_type = subsystem_type
        self.user = user
        self.group = group

        if subsystem_type not in QUARKUS_SUBSYSTEMS:
            raise ValueError(
                'Unsupported Quarkus subsystem type: %s. '
                'Supported types: %s' % (subsystem_type, ', '.join(QUARKUS_SUBSYSTEMS))
            )

    def __repr__(self):
        return '%s (%s-quarkus)' % (self.name, self.subsystem_type)

    @property
    def base_dir(self):
        return os.path.join(self.BASE_DIR, self.name)

    @property
    def conf_dir(self):
        return os.path.join(self.base_dir, 'conf')

    @property
    def actual_conf_dir(self):
        return os.path.join(self.CONFIG_DIR, self.name)

    @property
    def logs_dir(self):
        return os.path.join(self.base_dir, 'logs')

    @property
    def actual_logs_dir(self):
        return os.path.join(self.LOG_DIR, self.name)

    @property
    def alias_dir(self):
        return os.path.join(self.base_dir, 'alias')

    @property
    def cs_cfg(self):
        """Path to the CS.cfg configuration file."""
        return os.path.join(self.conf_dir, self.subsystem_type, 'CS.cfg')

    @property
    def application_yaml(self):
        """Path to the Quarkus application.yaml."""
        return os.path.join(self.conf_dir, self.subsystem_type, 'application.yaml')

    @property
    def runner_jar(self):
        """Path to the Quarkus runner JAR."""
        return os.path.join(
            self.SHARE_DIR,
            '%s-quarkus' % self.subsystem_type,
            'quarkus-app',
            'quarkus-run.jar'
        )

    @property
    def service_name(self):
        """systemd service name for this instance."""
        return 'pki-quarkusd@%s-%s' % (self.name, self.subsystem_type)

    @property
    def unit_file(self):
        """Path to the systemd unit file link."""
        return os.path.join(
            self.TARGET_WANTS,
            '%s.service' % self.service_name
        )

    def exists(self):
        """Check if this Quarkus instance exists."""
        return os.path.exists(self.base_dir) and os.path.exists(self.cs_cfg)

    def create(self, force=False):
        """
        Create the Quarkus instance directory structure.

        Creates:
          - Base directory
          - Config directory (symlinked)
          - Log directory (symlinked)
          - Alias directory for NSS database
          - Subsystem config directory
        """
        logger.info('Creating Quarkus instance: %s', self)

        # Create base directory
        os.makedirs(self.base_dir, exist_ok=True)

        # Create actual config and log directories
        os.makedirs(self.actual_conf_dir, exist_ok=True)
        os.makedirs(self.actual_logs_dir, exist_ok=True)

        # Create symlinks
        conf_link = self.conf_dir
        if not os.path.exists(conf_link):
            os.symlink(self.actual_conf_dir, conf_link)

        logs_link = self.logs_dir
        if not os.path.exists(logs_link):
            os.symlink(self.actual_logs_dir, logs_link)

        # Create alias directory
        os.makedirs(self.alias_dir, exist_ok=True)

        # Create subsystem config directory
        subsystem_conf_dir = os.path.join(self.conf_dir, self.subsystem_type)
        os.makedirs(subsystem_conf_dir, exist_ok=True)

        logger.info('Quarkus instance created: %s', self.base_dir)

    def remove(self, remove_conf=False, remove_logs=False, force=False):
        """Remove the Quarkus instance."""
        logger.info('Removing Quarkus instance: %s', self)

        # Remove systemd unit file link
        if os.path.exists(self.unit_file):
            logger.info('Removing %s', self.unit_file)
            os.unlink(self.unit_file)

        if remove_conf and os.path.exists(self.actual_conf_dir):
            logger.info('Removing %s', self.actual_conf_dir)
            import shutil
            shutil.rmtree(self.actual_conf_dir)

        if remove_logs and os.path.exists(self.actual_logs_dir):
            logger.info('Removing %s', self.actual_logs_dir)
            import shutil
            shutil.rmtree(self.actual_logs_dir)

        if os.path.exists(self.base_dir):
            logger.info('Removing %s', self.base_dir)
            import shutil
            shutil.rmtree(self.base_dir)

    def start(self):
        """Start the Quarkus subsystem via systemd."""
        logger.info('Starting %s', self.service_name)
        subprocess.run(
            ['systemctl', 'start', self.service_name],
            check=True
        )

    def stop(self):
        """Stop the Quarkus subsystem via systemd."""
        logger.info('Stopping %s', self.service_name)
        subprocess.run(
            ['systemctl', 'stop', self.service_name],
            check=True
        )

    def restart(self):
        """Restart the Quarkus subsystem via systemd."""
        logger.info('Restarting %s', self.service_name)
        subprocess.run(
            ['systemctl', 'restart', self.service_name],
            check=True
        )

    def is_running(self):
        """Check if the Quarkus subsystem is running."""
        result = subprocess.run(
            ['systemctl', 'is-active', self.service_name],
            capture_output=True, text=True
        )
        return result.returncode == 0

    def status(self):
        """Get the status of the Quarkus subsystem."""
        result = subprocess.run(
            ['systemctl', 'status', self.service_name],
            capture_output=True, text=True
        )
        return result.stdout

    def get_java_command(self):
        """
        Build the Java command to run the Quarkus subsystem directly.

        Returns a list of command arguments suitable for subprocess.
        """
        cmd = ['java']

        # Set instance directory for QuarkusInstanceConfig
        cmd.append('-Dpki.instance.dir=%s' % self.base_dir)

        # Set subsystem type
        cmd.append('-Dpki.subsystem.type=%s' % self.subsystem_type)

        # Set config file location
        cmd.append('-Dquarkus.config.locations=%s' % self.application_yaml)

        # NSS database path
        cmd.append('-Dpki.nss.database=%s' % self.alias_dir)

        # Quarkus runner JAR
        cmd.append('-jar')
        cmd.append(self.runner_jar)

        return cmd

    def generate_application_yaml(self, http_port=8080, https_port=8443):
        """
        Generate a default application.yaml for this subsystem.

        Exports the SSL server certificate and key from the NSS database
        as PEM files and configures the Quarkus TLS Registry to use them.

        Args:
            http_port: HTTP port (default 8080)
            https_port: HTTPS port (default 8443)
        """
        import tempfile
        import yaml

        subsystem_conf_dir = os.path.join(self.conf_dir, self.subsystem_type)
        os.makedirs(subsystem_conf_dir, exist_ok=True)

        # Export server cert and key from NSS database as PEM files
        cert_path = os.path.join(self.conf_dir, 'server-cert.pem')
        key_path = os.path.join(self.conf_dir, 'server-key.pem')
        self._export_server_cert_to_pem(cert_path, key_path)

        config = {
            'quarkus': {
                'application': {
                    'name': 'pki-%s-quarkus' % self.subsystem_type,
                },
                'tls': {
                    'key-store': {
                        'pem': {
                            '0': {
                                'cert': cert_path,
                                'key': key_path,
                            },
                        },
                    },
                },
                'http': {
                    'port': http_port,
                    'ssl-port': https_port,
                    'insecure-requests': 'enabled',
                },
                'log': {
                    'level': 'INFO',
                    'console': {
                        'enable': True,
                        'format': '%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c{3.}] (%t) %s%e%n',
                    },
                },
            }
        }

        yaml_path = os.path.join(subsystem_conf_dir, 'application.yaml')
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False)

        logger.info('Generated %s', yaml_path)

    def _export_server_cert_to_pem(self, cert_path, key_path):
        """
        Export the SSL server certificate chain and private key from
        the NSS database as PEM files for use by Quarkus TLS.

        The cert PEM contains the server certificate followed by the
        CA signing certificate (leaf-first order).

        Args:
            cert_path: Path to write the certificate chain PEM file.
            key_path: Path to write the private key PEM file.
        """
        import tempfile

        nss_db = self.alias_dir

        # Find the server cert nickname from the NSS database
        nickname = None
        result = subprocess.run(
            ['certutil', '-L', '-d', nss_db],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if 'Server-Cert' in line:
                nickname = line.rsplit(None, 1)[0].strip()
                break

        if not nickname:
            raise ValueError('Server certificate not found in NSS database %s' % nss_db)

        # Find the CA signing cert nickname
        ca_nickname = None
        for line in result.stdout.splitlines():
            if 'caSigningCert' in line:
                ca_nickname = line.rsplit(None, 1)[0].strip()
                break

        logger.info('Exporting %s to PEM files', nickname)

        # Export server cert (leaf first), then CA cert
        server_cert = subprocess.run(
            ['certutil', '-L', '-d', nss_db, '-n', nickname, '-a'],
            capture_output=True, text=True, check=True
        )

        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(server_cert.stdout)
            if ca_nickname:
                ca_cert = subprocess.run(
                    ['certutil', '-L', '-d', nss_db, '-n', ca_nickname, '-a'],
                    capture_output=True, text=True, check=True
                )
                f.write(ca_cert.stdout)

        # Read the NSS internal token password from password.conf
        password_conf = os.path.join(self.conf_dir, 'password.conf')
        nss_password = None
        with open(password_conf, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('internal='):
                    nss_password = line.split('=', 1)[1]
                    break

        if not nss_password:
            raise ValueError('Internal token password not found in %s' % password_conf)

        # Export key via pk12util + openssl (NSS has no direct key export)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as pw_file:
            pw_file.write(nss_password)
            pw_file_path = pw_file.name

        p12_tmp = cert_path + '.tmp.p12'
        try:
            subprocess.run(
                ['pk12util', '-o', p12_tmp, '-d', nss_db,
                 '-n', nickname, '-k', pw_file_path, '-w', pw_file_path],
                check=True
            )
            # Extract private key as clean PEM using openssl
            extract = subprocess.run(
                ['openssl', 'pkcs12', '-in', p12_tmp,
                 '-passin', 'pass:' + nss_password,
                 '-nocerts', '-nodes'],
                capture_output=True, text=True, check=True
            )
            # Pipe through openssl rsa to strip Bag Attributes
            clean = subprocess.run(
                ['openssl', 'rsa'],
                input=extract.stdout,
                capture_output=True, text=True, check=True
            )
            with open(key_path, 'w', encoding='utf-8') as f:
                f.write(clean.stdout)
        finally:
            os.unlink(pw_file_path)
            if os.path.exists(p12_tmp):
                os.unlink(p12_tmp)

        os.chmod(cert_path, 0o640)
        os.chmod(key_path, 0o600)

        return nss_password

    @staticmethod
    def find_instances():
        """
        Find all Quarkus PKI instances on the system.

        Returns a list of QuarkusPKIInstance objects.
        """
        instances = []
        base_dir = QuarkusPKIInstance.BASE_DIR

        if not os.path.exists(base_dir):
            return instances

        for name in sorted(os.listdir(base_dir)):
            instance_dir = os.path.join(base_dir, name)
            if not os.path.isdir(instance_dir):
                continue

            # Check for Quarkus subsystem configs
            conf_dir = os.path.join(instance_dir, 'conf')
            if not os.path.exists(conf_dir):
                continue

            for subsystem_type in QUARKUS_SUBSYSTEMS:
                cs_cfg = os.path.join(conf_dir, subsystem_type, 'CS.cfg')
                app_yaml = os.path.join(conf_dir, subsystem_type, 'application.yaml')
                if os.path.exists(cs_cfg) or os.path.exists(app_yaml):
                    instance = QuarkusPKIInstance(name, subsystem_type)
                    instances.append(instance)

        return instances
