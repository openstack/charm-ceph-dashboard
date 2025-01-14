#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

import json
import os
import socket
import tempfile
from typing import List, Tuple
from functools import partial

import subprocess
import logging

from charm_option import CharmCephOption

logger = logging.getLogger(__name__)


def _run_cmd(cmd: List[str]):
    """Run command in subprocess

    `cmd` The command to run
    """
    return subprocess.check_output(
        cmd, stderr=subprocess.STDOUT
    ).decode('UTF-8')


def exec_option_ceph_cmd(option: CharmCephOption, value: str) -> None:
    """Execute internal ceph command for the CharmCephOption"""
    _run_cmd(option.ceph_command(value))


def ceph_dashboard_delete_user(user: str) -> None:
    """Delete Ceph dashboard user."""
    cmd = ['ceph', 'dashboard', 'ac-user-delete', user]
    _run_cmd(cmd)


def ceph_dashboard_add_user(user: str, filename: str, role: str) -> str:
    """Create Ceph dashboard user."""
    cmd = [
        'ceph', 'dashboard', 'ac-user-create', '--enabled',
        '-i', filename, user, role
    ]
    return _run_cmd(cmd)


def ceph_dashboard_config_saml(
        base_url: str, idp_meta: str,
        username_attr: str, idp_entity_id: str
) -> None:
    """Configure SSO SAML2"""
    cmd = [
        'ceph', 'dashboard', 'sso', 'setup', 'saml2',
        base_url, idp_meta
    ]
    if username_attr:
        cmd.append(username_attr)

    if idp_entity_id:
        cmd.append(idp_entity_id)
    _run_cmd(cmd)


def ceph_config_get(key: str) -> str:
    "Fetch Value for a particular ceph-config key."
    cmd = [
        "ceph", "config-key", "get", key
    ]
    try:
        return _run_cmd(cmd)
    except subprocess.CalledProcessError:
        logger.error("Failed to fetch key %s", key)


def ceph_config_list() -> list:
    "Fetch list of ceph-config keys."
    cmd = [
        "ceph", "config-key", "ls"
    ]

    # CLI returns empty list if no config-key is configured.
    return json.loads(_run_cmd(cmd))


def ceph_config_set(key: str, value: str) -> None:
    "Remove the provided key/value pair"
    cmd = ["ceph", "config-key", "set", key, value]

    logging.debug("Setting config-key: %s", key)
    _run_cmd(cmd)


def ceph_config_reset(key: str) -> None:
    "Remove the provided key/value pair"
    cmd = ["ceph", "config-key", "rm", key]

    logging.debug("Removing config-key: %s", key)
    _run_cmd(cmd)


def dashboard_set(prop: str, value: str) -> str:
    "Configure ceph dashboard properties"
    logger.debug("Setting Dashboard %s as %s", prop, value)
    return _run_cmd(["ceph", "dashboard", prop, value])


def apply_setting(ceph_setting: str, value: List[str]) -> str:
    """Apply a dashboard setting"""
    cmd = ["ceph", "dashboard", ceph_setting]
    cmd.extend(value)
    return _run_cmd(cmd)


get_ceph_dashboard_ssl_key = partial(ceph_config_get, "mgr/dashboard/key")
get_ceph_dashboard_ssl_crt = partial(ceph_config_get, "mgr/dashboard/crt")
get_ceph_dashboard_host_ssl_key = partial(
    ceph_config_get, f"mgr/dashboard/{socket.gethostname()}/key"
)
get_ceph_dashboard_host_ssl_crt = partial(
    ceph_config_get, f"mgr/dashboard/{socket.gethostname()}/crt"
)


def check_ceph_dashboard_ssl_enabled() -> bool:
    """Check if ssl config-key is set to true"""
    ssl_status = ceph_config_get("config/mgr/mgr/dashboard/ssl")
    return ssl_status == "true"


def check_ceph_dashboard_ssl_configured(
        is_check_host_key: bool = False) -> bool:
    """Check if SSL key and certificate are configured on ceph dashboard."""
    if is_check_host_key:
        keys = [
            f"mgr/dashboard/{socket.gethostname()}/crt",
            f"mgr/dashboard/{socket.gethostname()}/key",
        ]
    else:
        keys = [  # List of keys to check for ssl configuration
            "mgr/dashboard/crt",
            "mgr/dashboard/key"
        ]

    for key in keys:
        value = ceph_config_get(key)
        if value is None:
            return False

    return True


def validate_ssl_keypair(cert: bytes, key: bytes) -> Tuple[bool, str]:
    """Validates if a private key matches a certificate

    Args:
        cert, key (str): SSL material

    Returns:
        Tuple[bool, str]: bool for validaity and err message
    """
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_temp:
            cert_temp.write(cert)
            cert_path = cert_temp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_temp:
            key_temp.write(key)
            key_path = key_temp.name
    except IOError as e:
        return False, f"Failed to create temporary files: {str(e)}"

    try:
        # check if pubkeys from cert and key match
        try:
            cert_pubkey_cmd = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"],
                capture_output=True,
                text=True,
                check=True,
            )
            cert_pubkey = cert_pubkey_cmd.stdout.strip()
        except subprocess.CalledProcessError as e:
            return (
                False,
                f"Failed to extract pubkey from cert: {e.stderr.strip()}",
            )

        try:
            key_pubkey_cmd = subprocess.run(
                ["openssl", "rsa", "-in", key_path, "-pubout"],
                capture_output=True,
                text=True,
                check=True,
            )
            key_pubkey = key_pubkey_cmd.stdout.strip()
        except subprocess.CalledProcessError as e:
            return (
                False,
                f"Failed to extract pubkey from priv key: {e.stderr.strip()}",
            )

        if cert_pubkey != key_pubkey:
            return False, "Certificate and private key do not match"

        return (
            True,
            "Certificate and private key match and certificate is valid",
        )

    finally:
        # Best effort clean up
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except Exception:
            pass
