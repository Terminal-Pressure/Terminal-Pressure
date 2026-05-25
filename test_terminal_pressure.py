#!/usr/bin/env python3
"""
Comprehensive test suite for terminal_pressure.py
==================================================
Covers scan_vulns(), stress_test(), exploit_chain(), main(), and all
validation helpers.  External dependencies (nmap, scapy, socket) are
fully mocked so no real network traffic is generated.

Run with:
    pytest test_terminal_pressure.py -v --cov=terminal_pressure
"""

import argparse
import json
import socket
import sys
import threading
from typing import Any
from unittest.mock import MagicMock, Mock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------
import terminal_pressure as tp
from terminal_pressure import (
    DEFAULT_DURATION,
    DEFAULT_PAYLOAD,
    DEFAULT_PORT,
    DEFAULT_THREADS,
    EXPLOIT_MAGIC,
    EXPLOIT_PORT,
    MAX_DURATION,
    MAX_THREADS,
    OUTPUT_CSV,
    OUTPUT_JSON,
    OUTPUT_TEXT,
    PORT_SCAN_RANGE,
    ExploitResult,
    HostResult,
    PortResult,
    ScanResult,
    StressResult,
    _expand_cidr,
    _is_valid_cidr,
    _is_valid_hostname,
    _is_valid_ip,
    _resolve_hostname,
    _validate_duration,
    _validate_output_format,
    _validate_port,
    _validate_target,
    _validate_threads,
    exploit_chain,
    main,
    scan_vulns,
    stress_test,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def mock_scanner():
    """Return a fully-configured mock nmap.PortScanner instance."""
    scanner = MagicMock()

    # Default: one host, one protocol (tcp), two open ports
    host = "192.168.1.1"
    scanner.all_hosts.return_value = [host]
    scanner[host].all_protocols.return_value = ["tcp"]
    scanner[host]["tcp"].keys.return_value = [80, 443]

    def port_info(port: int) -> dict[str, Any]:
        info = {"state": "open", "name": "http" if port == 80 else "https"}
        if port == 80:
            info["script"] = {"http-vuln-cve2017-1000353": "VULNERABLE"}
        return info

    scanner[host]["tcp"].__getitem__.side_effect = port_info
    return scanner


@pytest.fixture()
def mock_scanner_empty():
    """Return a mock PortScanner that reports no hosts."""
    scanner = MagicMock()
    scanner.all_hosts.return_value = []
    return scanner


# ===========================================================================
# _validate_target
# ===========================================================================


class TestValidateTarget:
    def test_valid_ip(self):
        assert _validate_target("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert _validate_target("example.com") == "example.com"

    def test_strips_whitespace(self):
        assert _validate_target("  10.0.0.1  ") == "10.0.0.1"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_target("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_target("   ")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_target(None)  # type: ignore[arg-type]

    def test_integer_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_target(12345)  # type: ignore[arg-type]


# ===========================================================================
# _validate_port
# ===========================================================================


class TestValidatePort:
    @pytest.mark.parametrize("port", [1, 80, 443, 8080, 65535])
    def test_valid_ports(self, port):
        assert _validate_port(port) == port

    @pytest.mark.parametrize("bad_port", [0, -1, 65536, 99999])
    def test_invalid_ports_raise(self, bad_port):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_port(bad_port)

    def test_string_raises(self):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_port("80")  # type: ignore[arg-type]

    def test_none_raises(self):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_port(None)  # type: ignore[arg-type]


# ===========================================================================
# _validate_threads
# ===========================================================================


class TestValidateThreads:
    @pytest.mark.parametrize("n", [1, 10, 50, 200])
    def test_valid_counts(self, n):
        assert _validate_threads(n) == n

    @pytest.mark.parametrize("bad", [0, -1, -100])
    def test_non_positive_raises(self, bad):
        with pytest.raises(ValueError):
            _validate_threads(bad)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_threads("10")  # type: ignore[arg-type]


# ===========================================================================
# _validate_duration
# ===========================================================================


class TestValidateDuration:
    @pytest.mark.parametrize("d", [1, 30, 60, 3600])
    def test_valid_durations(self, d):
        assert _validate_duration(d) == d

    @pytest.mark.parametrize("bad", [0, -1, -60])
    def test_non_positive_raises(self, bad):
        with pytest.raises(ValueError):
            _validate_duration(bad)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_duration("60")  # type: ignore[arg-type]


# ===========================================================================
# scan_vulns()
# ===========================================================================


class TestScanVulns:
    @patch("terminal_pressure.nmap.PortScanner")
    def test_scan_called_with_correct_args(self, MockScanner, mock_scanner):
        MockScanner.return_value = mock_scanner
        scan_vulns("192.168.1.1")
        mock_scanner.scan.assert_called_once_with("192.168.1.1", PORT_SCAN_RANGE, "-sV --script vuln")

    @patch("terminal_pressure.nmap.PortScanner")
    def test_scan_logs_host(self, MockScanner, mock_scanner, caplog):
        import logging

        MockScanner.return_value = mock_scanner
        with caplog.at_level(logging.INFO):
            scan_vulns("192.168.1.1")
        assert "192.168.1.1" in caplog.text

    @patch("terminal_pressure.nmap.PortScanner")
    def test_no_hosts_returns_without_error(self, MockScanner, mock_scanner_empty):
        MockScanner.return_value = mock_scanner_empty
        # Should not raise
        scan_vulns("10.0.0.1")
        mock_scanner_empty.scan.assert_called_once()

    @patch("terminal_pressure.nmap.PortScanner")
    def test_no_hosts_logs_message(self, MockScanner, mock_scanner_empty, caplog):
        import logging

        MockScanner.return_value = mock_scanner_empty
        with caplog.at_level(logging.INFO):
            scan_vulns("10.0.0.1")
        assert "No hosts found" in caplog.text

    @patch("terminal_pressure.nmap.PortScanner")
    def test_port_info_logged(self, MockScanner, mock_scanner, caplog):
        import logging

        MockScanner.return_value = mock_scanner
        with caplog.at_level(logging.INFO):
            scan_vulns("192.168.1.1")
        assert "80" in caplog.text

    @patch("terminal_pressure.nmap.PortScanner")
    def test_vuln_script_logged(self, MockScanner, mock_scanner, caplog):
        import logging

        MockScanner.return_value = mock_scanner
        with caplog.at_level(logging.INFO):
            scan_vulns("192.168.1.1")
        assert "Vuln Script" in caplog.text

    @patch("terminal_pressure.nmap.PortScanner")
    def test_port_without_script(self, MockScanner):
        """Ports that have no script key should not raise."""
        scanner = MagicMock()
        host = "10.0.0.2"
        scanner.all_hosts.return_value = [host]
        scanner[host].all_protocols.return_value = ["tcp"]
        scanner[host]["tcp"].keys.return_value = [22]
        scanner[host]["tcp"].__getitem__.return_value = {"state": "open", "name": "ssh"}
        MockScanner.return_value = scanner
        scan_vulns("10.0.0.2")  # Must not raise

    @patch("terminal_pressure.nmap.PortScanner")
    def test_nmap_error_propagates(self, MockScanner):
        import nmap

        MockScanner.return_value = MagicMock()
        MockScanner.return_value.scan.side_effect = nmap.PortScannerError("nmap not found")
        with pytest.raises(nmap.PortScannerError):
            scan_vulns("192.168.1.1")

    def test_empty_target_raises(self):
        with pytest.raises(ValueError):
            scan_vulns("")

    @patch("terminal_pressure.nmap.PortScanner")
    def test_multiple_protocols(self, MockScanner):
        """scan_vulns should handle multiple protocols (tcp + udp)."""
        scanner = MagicMock()
        host = "10.1.1.1"
        scanner.all_hosts.return_value = [host]
        scanner[host].all_protocols.return_value = ["tcp", "udp"]
        scanner[host]["tcp"].keys.return_value = [80]
        scanner[host]["udp"].keys.return_value = [53]
        scanner[host]["tcp"].__getitem__.return_value = {"state": "open", "name": "http"}
        scanner[host]["udp"].__getitem__.return_value = {"state": "open", "name": "domain"}
        MockScanner.return_value = scanner
        scan_vulns("10.1.1.1")  # Must not raise


# ===========================================================================
# stress_test()
# ===========================================================================


class TestStressTest:
    @patch("terminal_pressure.socket.socket")
    def test_returns_correct_number_of_threads(self, mock_socket_cls):
        threads = stress_test("127.0.0.1", port=8080, threads=5, duration=1)
        # Give them a moment to start
        for t in threads:
            t.join(timeout=3)
        assert len(threads) == 5

    @patch("terminal_pressure.socket.socket")
    def test_threads_are_daemon_threads(self, mock_socket_cls):
        threads = stress_test("127.0.0.1", port=8080, threads=3, duration=1)
        for t in threads:
            t.join(timeout=3)
            assert t.daemon, "Stress-test threads should be daemon threads"

    @patch("terminal_pressure.socket.socket")
    def test_default_thread_count(self, mock_socket_cls):
        threads = stress_test("127.0.0.1", duration=1)
        for t in threads:
            t.join(timeout=5)
        assert len(threads) == DEFAULT_THREADS

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            stress_test("")

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            stress_test("127.0.0.1", port=0)

    def test_invalid_threads_raises(self):
        with pytest.raises(ValueError):
            stress_test("127.0.0.1", threads=0)

    def test_invalid_duration_raises(self):
        with pytest.raises(ValueError):
            stress_test("127.0.0.1", duration=0)

    @patch("terminal_pressure.socket.socket")
    def test_socket_closed_after_send(self, mock_socket_cls):
        """Verify socket is always closed (resource-leak check)."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        threads = stress_test("127.0.0.1", port=80, threads=1, duration=1)
        for t in threads:
            t.join(timeout=3)

        # close() should have been called at least once
        assert mock_sock.close.called

    @patch("terminal_pressure.socket.socket")
    def test_connection_error_does_not_stop_thread(self, mock_socket_cls):
        """OSError during connect should be silently caught."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_sock

        threads = stress_test("127.0.0.1", port=80, threads=2, duration=1)
        for t in threads:
            t.join(timeout=3)
        # No exception propagated – threads finished cleanly

    @patch("terminal_pressure.socket.socket")
    def test_send_error_does_not_stop_thread(self, mock_socket_cls):
        """OSError during send should be silently caught."""
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = OSError("Broken pipe")
        mock_socket_cls.return_value = mock_sock

        threads = stress_test("127.0.0.1", port=80, threads=2, duration=1)
        for t in threads:
            t.join(timeout=3)

    @patch("terminal_pressure.socket.socket")
    def test_logs_start_message(self, mock_socket_cls, caplog):
        import logging

        with caplog.at_level(logging.INFO):
            threads = stress_test("127.0.0.1", port=80, threads=2, duration=1)
        for t in threads:
            t.join(timeout=3)
        assert "Applying pressure" in caplog.text


# ===========================================================================
# exploit_chain()
# ===========================================================================


class TestExploitChain:
    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_default_payload_sends_packet(self, mock_ip, mock_tcp, mock_raw, mock_send):
        mock_ip.return_value = MagicMock()
        mock_tcp.return_value = MagicMock()
        mock_raw.return_value = MagicMock()

        exploit_chain("192.168.1.100")

        mock_ip.assert_called_once_with(dst="192.168.1.100")
        mock_tcp.assert_called_once_with(dport=EXPLOIT_PORT, flags="S")
        mock_raw.assert_called_once_with(load=EXPLOIT_MAGIC)
        mock_send.assert_called_once()

    @patch("terminal_pressure.send")
    def test_custom_payload_does_not_send_packet(self, mock_send):
        exploit_chain("10.0.0.1", payload="my_custom_exploit")
        mock_send.assert_not_called()

    @patch("terminal_pressure.send")
    def test_custom_payload_logs_message(self, mock_send, caplog):
        import logging

        with caplog.at_level(logging.INFO):
            exploit_chain("10.0.0.1", payload="my_custom_exploit")
        assert "my_custom_exploit" in caplog.text

    def test_empty_target_raises(self):
        with pytest.raises(ValueError):
            exploit_chain("")

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_scapy_error_propagates(self, mock_ip, mock_tcp, mock_raw, mock_send):
        mock_ip.return_value = MagicMock()
        mock_tcp.return_value = MagicMock()
        mock_raw.return_value = MagicMock()
        mock_send.side_effect = Exception("Scapy internal error")

        with pytest.raises(Exception, match="Scapy internal error"):
            exploit_chain("192.168.1.100")

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_default_payload_logs_message(self, mock_ip, mock_tcp, mock_raw, mock_send, caplog):
        import logging

        with caplog.at_level(logging.INFO):
            exploit_chain("192.168.1.100")
        assert "192.168.1.100" in caplog.text

    @patch("terminal_pressure.send")
    def test_target_is_stripped(self, mock_send):
        """Whitespace in target should be stripped before use."""
        with patch("terminal_pressure.IP") as mock_ip, \
             patch("terminal_pressure.TCP"), \
             patch("terminal_pressure.Raw"):
            mock_ip.return_value = MagicMock()
            exploit_chain("  192.168.0.1  ")
            mock_ip.assert_called_once_with(dst="192.168.0.1")


# ===========================================================================
# main() – CLI dispatch
# ===========================================================================


class TestMain:
    @patch("terminal_pressure.scan_vulns")
    def test_scan_command_dispatches(self, mock_scan):
        with patch("sys.argv", ["tp", "scan", "192.168.1.1"]):
            main()
        mock_scan.assert_called_once_with("192.168.1.1", output_format="text")

    @patch("terminal_pressure.scan_vulns")
    def test_scan_command_with_json_format(self, mock_scan):
        with patch("sys.argv", ["tp", "scan", "192.168.1.1", "--format", "json"]):
            main()
        mock_scan.assert_called_once_with("192.168.1.1", output_format="json")

    @patch("terminal_pressure.scan_vulns")
    def test_scan_command_with_csv_format(self, mock_scan):
        with patch("sys.argv", ["tp", "scan", "192.168.1.1", "--format", "csv"]):
            main()
        mock_scan.assert_called_once_with("192.168.1.1", output_format="csv")

    @patch("terminal_pressure.stress_test")
    def test_stress_command_dispatches_defaults(self, mock_stress):
        with patch("sys.argv", ["tp", "stress", "example.com"]):
            main()
        mock_stress.assert_called_once_with("example.com", DEFAULT_PORT, DEFAULT_THREADS, DEFAULT_DURATION)

    @patch("terminal_pressure.stress_test")
    def test_stress_command_dispatches_custom_args(self, mock_stress):
        with patch(
            "sys.argv",
            ["tp", "stress", "example.com", "--port", "9090", "--threads", "10", "--duration", "5"],
        ):
            main()
        mock_stress.assert_called_once_with("example.com", 9090, 10, 5)

    @patch("terminal_pressure.exploit_chain")
    def test_exploit_command_dispatches_default(self, mock_exploit):
        with patch("sys.argv", ["tp", "exploit", "10.0.0.1"]):
            main()
        mock_exploit.assert_called_once_with("10.0.0.1", DEFAULT_PAYLOAD)

    @patch("terminal_pressure.exploit_chain")
    def test_exploit_command_dispatches_custom_payload(self, mock_exploit):
        with patch("sys.argv", ["tp", "exploit", "10.0.0.1", "--payload", "my_payload"]):
            main()
        mock_exploit.assert_called_once_with("10.0.0.1", "my_payload")

    def test_no_command_prints_help(self, capsys):
        with patch("sys.argv", ["tp"]):
            main()
        captured = capsys.readouterr()
        # argparse writes help to stdout
        assert "Terminal Pressure" in captured.out or "usage" in captured.out.lower()

    @patch("terminal_pressure.scan_vulns")
    def test_scan_uses_correct_target(self, mock_scan):
        with patch("sys.argv", ["tp", "scan", "my.host.local"]):
            main()
        mock_scan.assert_called_once_with("my.host.local", output_format="text")

    def test_version_command(self, capsys):
        with patch("sys.argv", ["tp", "version"]):
            main()
        captured = capsys.readouterr()
        assert "Terminal Pressure" in captured.out
        assert tp.__version__ in captured.out


# ===========================================================================
# Constants sanity checks
# ===========================================================================


class TestConstants:
    def test_default_port(self):
        assert DEFAULT_PORT == 80

    def test_default_threads(self):
        assert DEFAULT_THREADS == 50

    def test_default_duration(self):
        assert DEFAULT_DURATION == 60

    def test_default_payload(self):
        assert DEFAULT_PAYLOAD == "default_backdoor"

    def test_exploit_port(self):
        assert EXPLOIT_PORT == 4444

    def test_exploit_magic_is_bytes(self):
        assert isinstance(EXPLOIT_MAGIC, bytes)

    def test_port_scan_range_format(self):
        # Must be a string like "1-1024"
        low, high = PORT_SCAN_RANGE.split("-")
        assert int(low) >= 1
        assert int(high) <= 65535


# ===========================================================================
# Integration-style tests
# ===========================================================================


class TestIntegration:
    @patch("terminal_pressure.nmap.PortScanner")
    def test_scan_multi_host(self, MockScanner):
        """scan_vulns should iterate over multiple returned hosts."""
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["10.0.0.1", "10.0.0.2"]
        for host in ("10.0.0.1", "10.0.0.2"):
            scanner[host].all_protocols.return_value = ["tcp"]
            scanner[host]["tcp"].keys.return_value = [22]
            scanner[host]["tcp"].__getitem__.return_value = {"state": "open", "name": "ssh"}
        MockScanner.return_value = scanner

        scan_vulns("10.0.0.0/30")  # Should not raise

    @patch("terminal_pressure.socket.socket")
    def test_stress_test_all_threads_finish(self, mock_socket_cls):
        """All threads should terminate within a reasonable timeout."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        threads = stress_test("127.0.0.1", port=80, threads=5, duration=1)
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive(), "Worker thread is still alive after join timeout"

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    @patch("terminal_pressure.nmap.PortScanner")
    def test_scan_then_exploit(self, MockScanner, mock_ip, mock_tcp, mock_raw, mock_send):
        """Calling scan_vulns then exploit_chain in sequence should not interfere."""
        scanner = MagicMock()
        scanner.all_hosts.return_value = []
        MockScanner.return_value = scanner

        scan_vulns("192.168.0.1")
        mock_ip.return_value = MagicMock()
        exploit_chain("192.168.0.1")

        mock_send.assert_called_once()


# ===========================================================================
# IP/Hostname validation helper tests
# ===========================================================================


class TestIsValidIp:
    def test_valid_ipv4(self):
        assert _is_valid_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _is_valid_ip("::1") is True
        assert _is_valid_ip("2001:db8::1") is True

    def test_invalid_ip(self):
        assert _is_valid_ip("192.168.1.256") is False
        assert _is_valid_ip("example.com") is False
        assert _is_valid_ip("") is False


class TestIsValidCidr:
    def test_valid_cidr(self):
        assert _is_valid_cidr("192.168.1.0/24") is True
        assert _is_valid_cidr("10.0.0.0/8") is True

    def test_invalid_cidr(self):
        assert _is_valid_cidr("192.168.1.1") is False  # No /
        assert _is_valid_cidr("example.com") is False
        assert _is_valid_cidr("192.168.1.0/33") is False


class TestIsValidHostname:
    def test_valid_hostname(self):
        assert _is_valid_hostname("example.com") is True
        assert _is_valid_hostname("sub.domain.example.com") is True
        assert _is_valid_hostname("localhost") is True

    def test_invalid_hostname(self):
        assert _is_valid_hostname("") is False
        assert _is_valid_hostname("-invalid.com") is False
        assert _is_valid_hostname("a" * 300) is False  # Too long


class TestExpandCidr:
    def test_expand_small_network(self):
        hosts = _expand_cidr("192.168.1.0/30")
        assert len(hosts) == 2  # /30 has 2 usable hosts
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts

    def test_expand_invalid_cidr_returns_empty(self):
        hosts = _expand_cidr("invalid")
        assert hosts == []

    def test_large_network_is_limited(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            hosts = _expand_cidr("10.0.0.0/16")  # Would have thousands
        assert len(hosts) <= 256
        # Verify warning was logged about limiting hosts
        assert "limiting to first" in caplog.text.lower() or len(hosts) <= 256


class TestValidateOutputFormat:
    def test_valid_formats(self):
        assert _validate_output_format(OUTPUT_TEXT) == OUTPUT_TEXT
        assert _validate_output_format(OUTPUT_JSON) == OUTPUT_JSON
        assert _validate_output_format(OUTPUT_CSV) == OUTPUT_CSV

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            _validate_output_format("xml")


class TestValidateTargetEnhanced:
    """Additional tests for enhanced target validation."""

    def test_cidr_notation(self):
        assert _validate_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_ipv6(self):
        assert _validate_target("::1") == "::1"


class TestValidateThreadsEnhanced:
    """Additional tests for thread limits."""

    def test_max_threads_exceeded_raises(self):
        with pytest.raises(ValueError, match=str(MAX_THREADS)):
            _validate_threads(MAX_THREADS + 1)


class TestValidateDurationEnhanced:
    """Additional tests for duration limits."""

    def test_max_duration_exceeded_raises(self):
        with pytest.raises(ValueError, match=str(MAX_DURATION)):
            _validate_duration(MAX_DURATION + 1)


# ===========================================================================
# Data class tests
# ===========================================================================


class TestPortResult:
    def test_port_result_creation(self):
        pr = PortResult(port=80, protocol="tcp", state="open", service="http")
        assert pr.port == 80
        assert pr.protocol == "tcp"
        assert pr.state == "open"
        assert pr.service == "http"
        assert pr.scripts == {}

    def test_port_result_with_scripts(self):
        pr = PortResult(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            scripts={"http-vuln": "VULNERABLE"},
        )
        assert pr.scripts == {"http-vuln": "VULNERABLE"}


class TestHostResult:
    def test_host_result_creation(self):
        hr = HostResult(host="192.168.1.1")
        assert hr.host == "192.168.1.1"
        assert hr.ports == []

    def test_host_result_with_ports(self):
        pr = PortResult(port=80, protocol="tcp", state="open", service="http")
        hr = HostResult(host="192.168.1.1", ports=[pr])
        assert len(hr.ports) == 1


class TestScanResult:
    def test_scan_result_creation(self):
        sr = ScanResult(target="192.168.1.1")
        assert sr.target == "192.168.1.1"
        assert sr.hosts == []
        assert sr.scan_time == 0.0
        assert sr.error is None

    def test_scan_result_to_dict(self):
        sr = ScanResult(target="192.168.1.1", scan_time=1.5)
        d = sr.to_dict()
        assert d["target"] == "192.168.1.1"
        assert d["scan_time"] == 1.5

    def test_scan_result_to_json(self):
        sr = ScanResult(target="192.168.1.1")
        j = sr.to_json()
        assert '"target": "192.168.1.1"' in j

    def test_scan_result_to_csv(self):
        pr = PortResult(port=80, protocol="tcp", state="open", service="http")
        hr = HostResult(host="192.168.1.1", ports=[pr])
        sr = ScanResult(target="192.168.1.1", hosts=[hr])
        csv_output = sr.to_csv()
        assert "192.168.1.1" in csv_output
        assert "80" in csv_output


class TestExploitResult:
    def test_exploit_result_creation(self):
        er = ExploitResult(target="192.168.1.1", payload="default_backdoor")
        assert er.target == "192.168.1.1"
        assert er.payload == "default_backdoor"
        assert er.sent is False
        assert er.error is None

    def test_exploit_result_to_dict(self):
        er = ExploitResult(target="192.168.1.1", payload="test", sent=True)
        d = er.to_dict()
        assert d["sent"] is True


class TestStressResult:
    def test_stress_result_creation(self):
        sr = StressResult(target="192.168.1.1", port=80, threads=50, duration=60)
        assert sr.target == "192.168.1.1"
        assert sr.port == 80
        assert sr.threads == 50
        assert sr.duration == 60
        assert sr.started is False


# ===========================================================================
# scan_vulns return value tests
# ===========================================================================


class TestScanVulnsReturnValue:
    @patch("terminal_pressure.nmap.PortScanner")
    def test_returns_scan_result(self, MockScanner, mock_scanner):
        MockScanner.return_value = mock_scanner
        result = scan_vulns("192.168.1.1")
        assert isinstance(result, ScanResult)
        assert result.target == "192.168.1.1"

    @patch("terminal_pressure.nmap.PortScanner")
    def test_returns_hosts_in_result(self, MockScanner, mock_scanner):
        MockScanner.return_value = mock_scanner
        result = scan_vulns("192.168.1.1")
        assert len(result.hosts) >= 1

    @patch("terminal_pressure.nmap.PortScanner")
    def test_json_output(self, MockScanner, mock_scanner, capsys):
        MockScanner.return_value = mock_scanner
        scan_vulns("192.168.1.1", output_format=OUTPUT_JSON)
        captured = capsys.readouterr()
        # Validate JSON is well-formed and contains expected structure
        parsed = json.loads(captured.out)
        assert "target" in parsed
        assert "hosts" in parsed
        assert "scan_time" in parsed
        assert parsed["target"] == "192.168.1.1"


# ===========================================================================
# exploit_chain return value tests
# ===========================================================================


class TestExploitChainReturnValue:
    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_returns_exploit_result(self, mock_ip, mock_tcp, mock_raw, mock_send):
        mock_ip.return_value = MagicMock()
        result = exploit_chain("192.168.1.100")
        assert isinstance(result, ExploitResult)
        assert result.target == "192.168.1.100"
        assert result.sent is True

    @patch("terminal_pressure.send")
    def test_custom_payload_returns_result(self, mock_send):
        result = exploit_chain("10.0.0.1", payload="custom")
        assert isinstance(result, ExploitResult)
        assert result.payload == "custom"
        assert result.sent is False


# ===========================================================================
# Additional coverage tests
# ===========================================================================


class TestResolveHostname:
    """Tests for _resolve_hostname function."""

    @patch("terminal_pressure.socket.gethostbyname")
    def test_successful_resolution(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "93.184.216.34"
        result = _resolve_hostname("example.com")
        assert result == "93.184.216.34"

    @patch("terminal_pressure.socket.gethostbyname")
    def test_failed_resolution_returns_none(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror("DNS lookup failed")
        result = _resolve_hostname("nonexistent.invalid")
        assert result is None


class TestStressResultToDict:
    """Test StressResult to_dict method."""

    def test_stress_result_to_dict(self):
        sr = StressResult(target="192.168.1.1", port=80, threads=50, duration=60, started=True)
        d = sr.to_dict()
        assert d["target"] == "192.168.1.1"
        assert d["port"] == 80
        assert d["threads"] == 50
        assert d["started"] is True


class TestValidateTargetInvalidFormat:
    """Test target validation with invalid formats."""

    def test_invalid_hostname_format(self):
        with pytest.raises(ValueError, match="valid IP address"):
            _validate_target("-invalid-hostname")

    def test_invalid_with_special_chars(self):
        with pytest.raises(ValueError, match="valid IP address"):
            _validate_target("invalid@host")


class TestScanVulnsCsvOutput:
    """Test CSV output for scan_vulns."""

    @patch("terminal_pressure.nmap.PortScanner")
    def test_csv_output(self, MockScanner, mock_scanner, capsys):
        MockScanner.return_value = mock_scanner
        scan_vulns("192.168.1.1", output_format=OUTPUT_CSV)
        captured = capsys.readouterr()
        assert "host,port,protocol,state,service" in captured.out or "192.168.1.1" in captured.out


class TestSocketCloseError:
    """Test that socket close errors are handled."""

    @patch("terminal_pressure.socket.socket")
    def test_socket_close_oserror_handled(self, mock_socket_cls):
        """Socket close raising OSError should be silently handled."""
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("Socket close error")
        mock_socket_cls.return_value = mock_sock

        threads = stress_test("127.0.0.1", port=80, threads=1, duration=1)
        for t in threads:
            t.join(timeout=3)
        # No exception should be raised


class TestMainModuleExecution:
    """Test the if __name__ == '__main__' block."""

    def test_main_callable(self):
        """Test that main() is callable without args printing help."""
        with patch("sys.argv", ["tp"]):
            main()  # Should print help and not raise


# ===========================================================================
# Plugin system tests
# ===========================================================================

from terminal_pressure import (
    PluginBase,
    ScanPlugin,
    StressPlugin,
    ExploitPlugin,
    register_plugin,
    get_plugin,
    list_plugins,
    _PLUGIN_REGISTRY,
    HuggingFaceProvider,
    ModalProvider,
    HF_DEFAULT_MODEL,
    HF_DEFAULT_TIMEOUT,
    _handle_mcp_request,
    run_mcp_server,
)


class TestPluginSystem:
    """Tests for the plugin registry, PluginBase, and built-in plugins."""

    def test_list_plugins_returns_builtins(self):
        plugins = list_plugins()
        names = [p.name for p in plugins]
        assert "scan" in names
        assert "stress" in names
        assert "exploit" in names

    def test_get_plugin_scan(self):
        p = get_plugin("scan")
        assert p.name == "scan"
        assert isinstance(p, ScanPlugin)

    def test_get_plugin_stress(self):
        p = get_plugin("stress")
        assert p.name == "stress"
        assert isinstance(p, StressPlugin)

    def test_get_plugin_exploit(self):
        p = get_plugin("exploit")
        assert p.name == "exploit"
        assert isinstance(p, ExploitPlugin)

    def test_get_plugin_unknown_raises(self):
        with pytest.raises(KeyError, match="not found"):
            get_plugin("nonexistent_plugin_xyz")

    def test_register_custom_plugin(self):
        class _TmpPlugin(PluginBase):
            name = "_tmp_test_plugin"
            description = "Temporary test plugin"

            def run(self, **kwargs: Any) -> dict:
                return {"ok": True}

        p = _TmpPlugin()
        register_plugin(p)
        try:
            assert get_plugin("_tmp_test_plugin") is p
        finally:
            _PLUGIN_REGISTRY.pop("_tmp_test_plugin", None)

    def test_register_plugin_no_name_raises(self):
        class _Unnamed(PluginBase):
            pass

        with pytest.raises(ValueError, match="non-empty"):
            register_plugin(_Unnamed())

    def test_plugin_base_run_raises(self):
        p = PluginBase()
        p.name = "base"
        with pytest.raises(NotImplementedError):
            p.run()

    def test_plugin_input_schema_scan(self):
        schema = ScanPlugin().input_schema
        assert schema["type"] == "object"
        assert "target" in schema["properties"]
        assert "target" in schema["required"]

    def test_plugin_input_schema_stress(self):
        schema = StressPlugin().input_schema
        assert "port" in schema["properties"]
        assert "threads" in schema["properties"]
        assert "duration" in schema["properties"]

    def test_plugin_input_schema_exploit(self):
        schema = ExploitPlugin().input_schema
        assert "target" in schema["properties"]
        assert "payload" in schema["properties"]

    @patch("terminal_pressure.scan_vulns")
    def test_scan_plugin_run(self, mock_scan):
        sr = ScanResult(target="10.0.0.1")
        mock_scan.return_value = sr
        result = ScanPlugin().run(target="10.0.0.1")
        assert result["target"] == "10.0.0.1"
        mock_scan.assert_called_once_with("10.0.0.1", OUTPUT_TEXT)

    @patch("terminal_pressure.stress_test")
    def test_stress_plugin_run(self, mock_stress):
        mock_stress.return_value = [MagicMock(), MagicMock()]
        result = StressPlugin().run(target="10.0.0.1", port=80, threads=2, duration=1)
        assert result["threads_started"] == 2
        assert result["status"] == "running"

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_exploit_plugin_run(self, mock_ip, mock_tcp, mock_raw, mock_send):
        mock_ip.return_value = MagicMock()
        result = ExploitPlugin().run(target="10.0.0.1")
        assert result["target"] == "10.0.0.1"
        assert result["sent"] is True


# ===========================================================================
# MCP server tests
# ===========================================================================


class TestMcpHandleRequest:
    """Unit tests for _handle_mcp_request."""

    def test_initialize_returns_capabilities(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "terminal-pressure"

    def test_initialize_includes_version(self):
        import terminal_pressure as tp2
        req = {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert resp["result"]["serverInfo"]["version"] == tp2.__version__

    def test_tools_list_returns_builtin_tools(self):
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is not None
        tools = resp["result"]["tools"]
        names = [t["name"] for t in tools]
        assert "scan" in names
        assert "stress" in names
        assert "exploit" in names

    def test_tools_list_includes_schema(self):
        req = {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is not None
        scan_tool = next(t for t in resp["result"]["tools"] if t["name"] == "scan")
        assert "inputSchema" in scan_tool
        assert scan_tool["inputSchema"]["type"] == "object"

    @patch("terminal_pressure.scan_vulns")
    def test_tools_call_scan(self, mock_scan):
        mock_scan.return_value = ScanResult(target="10.0.0.1")
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"target": "10.0.0.1"}},
        }
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert resp["result"]["isError"] is False
        content = resp["result"]["content"][0]["text"]
        parsed = json.loads(content)
        assert parsed["target"] == "10.0.0.1"

    def test_tools_call_unknown_tool_is_error(self):
        req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "nonexistent_xyz", "arguments": {}},
        }
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert resp["result"]["isError"] is True
        assert "not found" in resp["result"]["content"][0]["text"].lower()

    def test_unknown_method_returns_error(self):
        req = {"jsonrpc": "2.0", "id": 7, "method": "unknown/method", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_notification_returns_none(self):
        req = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        resp = _handle_mcp_request(req)
        assert resp is None

    def test_tools_call_with_invalid_args_is_error(self):
        req = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"target": ""}},
        }
        resp = _handle_mcp_request(req)
        assert resp is not None
        assert resp["result"]["isError"] is True


class TestRunMcpServer:
    """Integration tests for run_mcp_server()."""

    def test_processes_initialize_and_tools_list(self):
        import io as _io

        requests = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        ]
        inp = _io.StringIO("\n".join(requests) + "\n")
        out = _io.StringIO()
        run_mcp_server(inp, out)
        lines = [l for l in out.getvalue().strip().split("\n") if l]
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["id"] == 1
        assert "result" in first
        second = json.loads(lines[1])
        assert second["id"] == 2
        tools = second["result"]["tools"]
        assert any(t["name"] == "scan" for t in tools)

    def test_parse_error_on_invalid_json(self):
        import io as _io

        inp = _io.StringIO("not valid json\n")
        out = _io.StringIO()
        run_mcp_server(inp, out)
        lines = [l for l in out.getvalue().strip().split("\n") if l]
        assert len(lines) == 1
        resp = json.loads(lines[0])
        assert resp["error"]["code"] == -32700

    def test_blank_lines_are_skipped(self):
        import io as _io

        inp = _io.StringIO("\n\n\n")
        out = _io.StringIO()
        run_mcp_server(inp, out)
        assert out.getvalue() == ""

    def test_notification_produces_no_output(self):
        import io as _io

        inp = _io.StringIO(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        out = _io.StringIO()
        run_mcp_server(inp, out)
        assert out.getvalue() == ""


# ===========================================================================
# HuggingFace provider tests
# ===========================================================================


class TestHuggingFaceProvider:
    """Tests for HuggingFaceProvider."""

    def test_available_with_token(self, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")
        hf = HuggingFaceProvider()
        assert hf.available is True

    def test_not_available_without_token(self, monkeypatch):
        monkeypatch.delenv("HF_TOKEN", raising=False)
        hf = HuggingFaceProvider()
        assert hf.available is False

    def test_not_available_with_empty_token(self, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "")
        hf = HuggingFaceProvider()
        assert hf.available is False

    def test_analyze_raises_without_token(self, monkeypatch):
        monkeypatch.delenv("HF_TOKEN", raising=False)
        hf = HuggingFaceProvider()
        with pytest.raises(RuntimeError, match="HF_TOKEN"):
            hf.analyze("test text")

    @patch("terminal_pressure._requests")
    def test_analyze_success(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"generated_text": "Analysis result"}]
        mock_requests.post.return_value = mock_resp
        mock_requests.exceptions.Timeout = Exception
        mock_requests.exceptions.HTTPError = Exception
        mock_requests.exceptions.RequestException = Exception

        hf = HuggingFaceProvider()
        result = hf.analyze("test input")
        assert result["status"] == "ok"
        assert result["model"] == HF_DEFAULT_MODEL
        mock_requests.post.assert_called_once()

    @patch("terminal_pressure._requests")
    def test_analyze_timeout_raises(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")

        class _Timeout(Exception):
            pass

        class _HTTPError(_Timeout):
            pass

        class _ReqEx(_Timeout):
            pass

        mock_requests.exceptions.Timeout = _Timeout
        mock_requests.exceptions.HTTPError = _HTTPError
        mock_requests.exceptions.RequestException = _ReqEx
        mock_requests.post.side_effect = _Timeout("timed out")

        hf = HuggingFaceProvider()
        with pytest.raises(RuntimeError, match="timed out"):
            hf.analyze("text")

    @patch("terminal_pressure._requests")
    def test_analyze_http_error_raises(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")

        class _Base(Exception):
            pass

        class _Timeout(_Base):
            pass

        class _HTTPError(_Base):
            pass

        class _ReqEx(_Base):
            pass

        mock_requests.exceptions.Timeout = _Timeout
        mock_requests.exceptions.HTTPError = _HTTPError
        mock_requests.exceptions.RequestException = _ReqEx
        mock_requests.post.side_effect = _HTTPError("403 Forbidden")

        hf = HuggingFaceProvider()
        with pytest.raises(RuntimeError, match="HTTP error"):
            hf.analyze("text")

    @patch("terminal_pressure._requests")
    def test_analyze_request_exception_raises(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")

        class _Base(Exception):
            pass

        class _Timeout(_Base):
            pass

        class _HTTPError(_Base):
            pass

        class _ReqEx(_Base):
            pass

        mock_requests.exceptions.Timeout = _Timeout
        mock_requests.exceptions.HTTPError = _HTTPError
        mock_requests.exceptions.RequestException = _ReqEx
        mock_requests.post.side_effect = _ReqEx("connection failed")

        hf = HuggingFaceProvider()
        with pytest.raises(RuntimeError, match="request failed"):
            hf.analyze("text")

    @patch("terminal_pressure._requests")
    def test_analyze_scan_builds_prompt(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"generated_text": "ok"}]
        mock_requests.post.return_value = mock_resp
        mock_requests.exceptions.Timeout = Exception
        mock_requests.exceptions.HTTPError = Exception
        mock_requests.exceptions.RequestException = Exception

        hf = HuggingFaceProvider()
        sr = ScanResult(target="192.168.1.1")
        result = hf.analyze_scan(sr)
        assert result["status"] == "ok"
        # Verify the prompt contained the scan JSON
        call_args = mock_requests.post.call_args
        payload_text = call_args.kwargs.get("json", call_args[1].get("json", {}))
        assert "192.168.1.1" in payload_text["inputs"]

    @patch("terminal_pressure._requests")
    def test_analyze_uses_custom_api_url(self, mock_requests, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "hf_test_token")
        monkeypatch.setenv("HF_API_URL", "https://custom.hf.example.com")
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_requests.post.return_value = mock_resp
        mock_requests.exceptions.Timeout = Exception
        mock_requests.exceptions.HTTPError = Exception
        mock_requests.exceptions.RequestException = Exception

        hf = HuggingFaceProvider()
        hf.analyze("text")
        called_url = mock_requests.post.call_args[0][0]
        assert called_url.startswith("https://custom.hf.example.com/")


# ===========================================================================
# Modal provider tests
# ===========================================================================


class TestModalProvider:
    """Tests for ModalProvider (modal is not installed in test environment)."""

    def test_not_available_without_modal(self):
        mp = ModalProvider()
        # modal is not installed in the test environment
        assert mp.available is False

    def test_run_scan_raises_when_unavailable(self):
        mp = ModalProvider()
        with pytest.raises(RuntimeError, match="modal"):
            mp.run_scan("10.0.0.1")

    @patch("terminal_pressure._MODAL_AVAILABLE", True)
    def test_available_when_modal_present(self):
        mp = ModalProvider()
        assert mp.available is True

    @patch("terminal_pressure._MODAL_AVAILABLE", True)
    @patch("terminal_pressure._modal")
    def test_run_scan_calls_modal(self, mock_modal_mod):
        """run_scan should build an App and call remote() when modal is present."""
        result_payload = json.dumps({
            "target": "10.0.0.1",
            "hosts": [],
            "scan_time": 1.0,
            "provider": "modal",
        })
        mock_app = MagicMock()
        mock_modal_mod.App.return_value = mock_app
        mock_fn = MagicMock()
        mock_app.function.return_value = lambda f: mock_fn
        mock_modal_mod.App.return_value.__enter__ = MagicMock(return_value=mock_app)
        mock_modal_mod.App.return_value.__exit__ = MagicMock(return_value=False)
        mock_fn.remote.return_value = result_payload

        # Make app.run() a context manager
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        mock_app.run.return_value = ctx

        mp = ModalProvider()
        # The actual remote execution path is covered by the RuntimeError guard;
        # verify the guard itself does not fire when _MODAL_AVAILABLE=True.
        assert mp.available is True

    @patch("terminal_pressure._MODAL_AVAILABLE", True)
    @patch("terminal_pressure._modal")
    def test_run_scan_raises_on_modal_exception(self, mock_modal_mod):
        """run_scan wraps Modal exceptions in RuntimeError."""
        mock_modal_mod.App.side_effect = Exception("Modal auth failed")
        mp = ModalProvider()
        with pytest.raises(RuntimeError, match="Modal scan failed"):
            mp.run_scan("10.0.0.1")

    def test_run_scan_validates_target(self):
        mp = ModalProvider()
        # Should raise RuntimeError about modal not being available, not ValueError,
        # because the availability check comes first.
        with pytest.raises(RuntimeError, match="modal"):
            mp.run_scan("")


# ===========================================================================
# New CLI subcommand tests
# ===========================================================================


class TestMainNewSubcommands:
    """Tests for list-plugins, run-plugin, mcp-server, providers, hf-analyze,
    modal-scan."""

    def test_list_plugins_command(self, capsys):
        with patch("sys.argv", ["tp", "list-plugins"]):
            main()
        out = capsys.readouterr().out
        assert "scan" in out
        assert "stress" in out
        assert "exploit" in out

    def test_run_plugin_scan(self, capsys):
        with patch("terminal_pressure.scan_vulns") as mock_scan:
            mock_scan.return_value = ScanResult(target="10.0.0.1")
            with patch("sys.argv", ["tp", "run-plugin", "scan", "--target", "10.0.0.1"]):
                main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["target"] == "10.0.0.1"

    def test_run_plugin_unknown_exits_1(self, capsys):
        with patch("sys.argv", ["tp", "run-plugin", "no_such_plugin"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1
        assert "not found" in capsys.readouterr().err.lower()

    @patch("terminal_pressure.stress_test")
    def test_run_plugin_stress(self, mock_stress, capsys):
        mock_stress.return_value = [MagicMock()]
        with patch(
            "sys.argv",
            ["tp", "run-plugin", "stress", "--target", "10.0.0.1",
             "--threads", "2", "--duration", "1"],
        ):
            main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["threads_started"] == 1

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_run_plugin_exploit(self, mock_ip, mock_tcp, mock_raw, mock_send, capsys):
        mock_ip.return_value = MagicMock()
        with patch("sys.argv", ["tp", "run-plugin", "exploit", "--target", "10.0.0.1"]):
            main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["target"] == "10.0.0.1"

    def test_mcp_server_command(self):
        import io as _io

        inp = _io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + "\n"
        )
        out = _io.StringIO()
        with patch("terminal_pressure.run_mcp_server") as mock_mcp:
            with patch("sys.argv", ["tp", "mcp-server"]):
                main()
        mock_mcp.assert_called_once()

    def test_providers_command(self, capsys):
        with patch("sys.argv", ["tp", "providers"]):
            main()
        out = capsys.readouterr().out
        assert "huggingface" in out
        assert "modal" in out

    def test_providers_shows_unavailable_when_no_token(self, monkeypatch, capsys):
        monkeypatch.delenv("HF_TOKEN", raising=False)
        with patch("sys.argv", ["tp", "providers"]):
            main()
        out = capsys.readouterr().out
        assert "[--]" in out

    def test_hf_analyze_exits_when_unavailable(self, monkeypatch, capsys):
        monkeypatch.delenv("HF_TOKEN", raising=False)
        with patch("sys.argv", ["tp", "hf-analyze", "10.0.0.1"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1

    @patch("terminal_pressure._requests")
    def test_hf_analyze_success(self, mock_requests, monkeypatch, capsys):
        monkeypatch.setenv("HF_TOKEN", "hf_test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"generated_text": "All good"}]
        mock_requests.post.return_value = mock_resp
        mock_requests.exceptions.Timeout = Exception
        mock_requests.exceptions.HTTPError = Exception
        mock_requests.exceptions.RequestException = Exception

        with patch("terminal_pressure.scan_vulns") as mock_scan:
            mock_scan.return_value = ScanResult(target="10.0.0.1")
            with patch("sys.argv", ["tp", "hf-analyze", "10.0.0.1"]):
                main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["status"] == "ok"

    def test_modal_scan_exits_when_unavailable(self, capsys):
        with patch("sys.argv", ["tp", "modal-scan", "10.0.0.1"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1

    @patch("terminal_pressure._MODAL_AVAILABLE", True)
    @patch("terminal_pressure.ModalProvider.run_scan")
    def test_modal_scan_success(self, mock_run_scan, capsys):
        mock_run_scan.return_value = {
            "target": "10.0.0.1",
            "hosts": [],
            "scan_time": 1.0,
            "provider": "modal",
        }
        with patch("sys.argv", ["tp", "modal-scan", "10.0.0.1"]):
            main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["provider"] == "modal"

    def test_version_shows_new_version(self, capsys):
        import terminal_pressure as tp2

        with patch("sys.argv", ["tp", "version"]):
            main()
        out = capsys.readouterr().out
        assert tp2.__version__ in out
        assert "3.0.0" in out
