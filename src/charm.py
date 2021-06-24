#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm for the Ceph Dashboard."""

import logging
import tempfile

from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, StatusBase
from ops.charm import ActionEvent
import interface_tls_certificates.ca_client as ca_client
import re
import secrets
import socket
import string
import subprocess
import ops_openstack.plugins.classes
import interface_dashboard
import interface_api_endpoints
import cryptography.hazmat.primitives.serialization as serialization
import charms_ceph.utils as ceph_utils

from pathlib import Path

logger = logging.getLogger(__name__)


class CephDashboardCharm(ops_openstack.core.OSBaseCharm):
    """Ceph Dashboard charm."""

    _stored = StoredState()
    PACKAGES = ['ceph-mgr-dashboard']
    CEPH_CONFIG_PATH = Path('/etc/ceph')
    TLS_KEY_PATH = CEPH_CONFIG_PATH / 'ceph-dashboard.key'
    TLS_PUB_KEY_PATH = CEPH_CONFIG_PATH / 'ceph-dashboard-pub.key'
    TLS_CERT_PATH = CEPH_CONFIG_PATH / 'ceph-dashboard.crt'
    TLS_KEY_AND_CERT_PATH = CEPH_CONFIG_PATH / 'ceph-dashboard.pem'
    TLS_CA_CERT_PATH = Path(
        '/usr/local/share/ca-certificates/vault_ca_cert_dashboard.crt')
    TLS_PORT = 8443

    def __init__(self, *args) -> None:
        """Setup adapters and observers."""
        super().__init__(*args)
        super().register_status_check(self.check_dashboard)
        self.mon = interface_dashboard.CephDashboardRequires(
            self,
            'dashboard')
        self.ca_client = ca_client.CAClient(
            self,
            'certificates')
        self.framework.observe(
            self.mon.on.mon_ready,
            self._configure_dashboard)
        self.framework.observe(
            self.ca_client.on.ca_available,
            self._on_ca_available)
        self.framework.observe(
            self.ca_client.on.tls_server_config_ready,
            self._on_tls_server_config_ready)
        self.framework.observe(self.on.add_user_action, self._add_user_action)
        self.ingress = interface_api_endpoints.APIEndpointsRequires(
            self,
            'loadbalancer',
            {
                'endpoints': [{
                    'service-type': 'ceph-dashboard',
                    'frontend-port': self.TLS_PORT,
                    'backend-port': self.TLS_PORT,
                    'backend-ip': self._get_bind_ip(),
                    'check-type': 'httpd'}]})
        self._stored.set_default(is_started=False)

    def _on_ca_available(self, _) -> None:
        """Request TLS certificates."""
        addresses = set()
        for binding_name in ['public']:
            binding = self.model.get_binding(binding_name)
            addresses.add(binding.network.ingress_address)
            addresses.add(binding.network.bind_address)
        sans = [str(s) for s in addresses]
        sans.append(socket.gethostname())
        if self.config.get('public-hostname'):
            sans.append(self.config.get('public-hostname'))
        self.ca_client.request_server_certificate(socket.getfqdn(), sans)

    def check_dashboard(self) -> StatusBase:
        """Check status of dashboard"""
        self._stored.is_started = ceph_utils.is_dashboard_enabled()
        if self._stored.is_started:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self._get_bind_ip(), self.TLS_PORT))
            if result == 0:
                return ActiveStatus()
            else:
                return BlockedStatus(
                    'Dashboard not responding')
        else:
            return BlockedStatus(
                'Dashboard is not enabled')
        return ActiveStatus()

    def kick_dashboard(self) -> None:
        """Disable and re-enable dashboard"""
        ceph_utils.mgr_disable_dashboard()
        ceph_utils.mgr_enable_dashboard()

    def _configure_dashboard(self, _) -> None:
        """Configure dashboard"""
        if self.unit.is_leader() and not ceph_utils.is_dashboard_enabled():
            ceph_utils.mgr_enable_dashboard()
        ceph_utils.mgr_config_set(
            'mgr/dashboard/{hostname}/server_addr'.format(
                hostname=socket.gethostname()),
            str(self._get_bind_ip()))
        self.update_status()

    def _get_bind_ip(self) -> str:
        """Return the IP to bind the dashboard to"""
        binding = self.model.get_binding('public')
        return str(binding.network.ingress_address)

    def _on_tls_server_config_ready(self, _) -> None:
        """Configure TLS."""
        self.TLS_KEY_PATH.write_bytes(
            self.ca_client.server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        self.TLS_CERT_PATH.write_bytes(
            self.ca_client.server_certificate.public_bytes(
                encoding=serialization.Encoding.PEM))
        self.TLS_CA_CERT_PATH.write_bytes(
            self.ca_client.ca_certificate.public_bytes(
                encoding=serialization.Encoding.PEM) +
            self.ca_client.root_ca_chain.public_bytes(
                encoding=serialization.Encoding.PEM))

        hostname = socket.gethostname()
        subprocess.check_call(['update-ca-certificates'])
        ceph_utils.dashboard_set_ssl_certificate(
            self.TLS_CERT_PATH,
            hostname=hostname)
        ceph_utils.dashboard_set_ssl_certificate_key(
            self.TLS_KEY_PATH,
            hostname=hostname)
        if self.unit.is_leader():
            ceph_utils.mgr_config_set(
                'mgr/dashboard/standby_behaviour',
                'redirect')
            ceph_utils.mgr_config_set(
                'mgr/dashboard/ssl',
                'true')
            # Set the ssl artifacte without the hostname which appears to
            # be required even though they aren't used.
            ceph_utils.dashboard_set_ssl_certificate(
                self.TLS_CERT_PATH)
            ceph_utils.dashboard_set_ssl_certificate_key(
                self.TLS_KEY_PATH)
        self.kick_dashboard()

    def _gen_user_password(self, length: int = 8) -> str:
        """Generate a password"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for i in range(length))

    def _add_user_action(self, event: ActionEvent) -> None:
        """Create a user"""
        username = event.params["username"]
        role = event.params["role"]
        if not all([username, role]):
            event.fail("Config missing")
        else:
            password = self._gen_user_password()
            with tempfile.NamedTemporaryFile(mode='w', delete=True) as fp:
                fp.write(password)
                fp.flush()
                cmd_out = subprocess.check_output([
                    'ceph', 'dashboard', 'ac-user-create', '--enabled',
                    '-i', fp.name, username, role]).decode('UTF-8')
                if re.match('User.*already exists', cmd_out):
                    event.fail("User already exists")
                else:
                    event.set_results({"password": password})

if __name__ == "__main__":
    main(CephDashboardCharm)
