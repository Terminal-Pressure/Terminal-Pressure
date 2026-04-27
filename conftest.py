"""
conftest.py – Shared pytest fixtures for Terminal Pressure test suite.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# nmap scanner fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_scanner():
    """Return a fully-configured mock nmap.PortScanner instance.

    Default configuration: one host (192.168.1.1), one protocol (tcp),
    two open ports (80 and 443) with a vuln script hit on port 80.
    """
    scanner = MagicMock()

    host = "192.168.1.1"
    scanner.all_hosts.return_value = [host]
    scanner[host].all_protocols.return_value = ["tcp"]
    scanner[host]["tcp"].keys.return_value = [80, 443]

    def _port_info(port: int) -> dict[str, Any]:
        info: dict[str, Any] = {
            "state": "open",
            "name": "http" if port == 80 else "https",
        }
        if port == 80:
            info["script"] = {"http-vuln-cve2017-1000353": "VULNERABLE"}
        return info

    scanner[host]["tcp"].__getitem__.side_effect = _port_info
    return scanner


@pytest.fixture()
def mock_scanner_empty():
    """Return a mock PortScanner that reports no hosts."""
    scanner = MagicMock()
    scanner.all_hosts.return_value = []
    return scanner


@pytest.fixture()
def mock_scanner_multi_host():
    """Return a mock PortScanner with two hosts."""
    scanner = MagicMock()
    hosts = ["10.0.0.1", "10.0.0.2"]
    scanner.all_hosts.return_value = hosts
    for h in hosts:
        scanner[h].all_protocols.return_value = ["tcp"]
        scanner[h]["tcp"].keys.return_value = [22]
        scanner[h]["tcp"].__getitem__.return_value = {"state": "open", "name": "ssh"}
    return scanner
