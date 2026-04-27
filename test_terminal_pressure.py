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
    OUTPUT_FORMAT_JSON,
    OUTPUT_FORMAT_TEXT,
    PORT_SCAN_RANGE,
    VALID_OUTPUT_FORMATS,
    VERSION,
    _configure_logging,
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
        with pytest.raises(ValueError):
            _validate_target(None)  # type: ignore[arg-type]

    def test_integer_raises(self):
        with pytest.raises(ValueError):
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
        with pytest.raises(ValueError):
            _validate_port(bad_port)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_port("80")  # type: ignore[arg-type]

    def test_none_raises(self):
        with pytest.raises(ValueError):
            _validate_port(None)  # type: ignore[arg-type]


# ===========================================================================
# _validate_threads
# ===========================================================================


class TestValidateThreads:
    @pytest.mark.parametrize("n", [1, 10, 50, 200, MAX_THREADS])
    def test_valid_counts(self, n):
        assert _validate_threads(n) == n

    @pytest.mark.parametrize("bad", [0, -1, -100])
    def test_non_positive_raises(self, bad):
        with pytest.raises(ValueError):
            _validate_threads(bad)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_threads("10")  # type: ignore[arg-type]

    def test_exceeds_max_raises(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            _validate_threads(MAX_THREADS + 1)


# ===========================================================================
# _validate_duration
# ===========================================================================


class TestValidateDuration:
    @pytest.mark.parametrize("d", [1, 30, 60, MAX_DURATION])
    def test_valid_durations(self, d):
        assert _validate_duration(d) == d

    @pytest.mark.parametrize("bad", [0, -1, -60])
    def test_non_positive_raises(self, bad):
        with pytest.raises(ValueError):
            _validate_duration(bad)

    def test_string_raises(self):
        with pytest.raises(ValueError):
            _validate_duration("60")  # type: ignore[arg-type]

    def test_exceeds_max_raises(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            _validate_duration(MAX_DURATION + 1)


# ===========================================================================
# _validate_output_format
# ===========================================================================


class TestValidateOutputFormat:
    @pytest.mark.parametrize("fmt", VALID_OUTPUT_FORMATS)
    def test_valid_formats(self, fmt):
        assert _validate_output_format(fmt) == fmt

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid output format"):
            _validate_output_format("xml")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            _validate_output_format("")


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
    def test_no_hosts_returns_empty_result(self, MockScanner, mock_scanner_empty):
        MockScanner.return_value = mock_scanner_empty
        result = scan_vulns("10.0.0.1")
        mock_scanner_empty.scan.assert_called_once()
        assert result["target"] == "10.0.0.1"
        assert result["hosts"] == []

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
        result = scan_vulns("10.0.0.2")
        assert len(result["hosts"]) == 1

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
        result = scan_vulns("10.1.1.1")
        assert len(result["hosts"]) == 1
        assert len(result["hosts"][0]["protocols"]) == 2

    @patch("terminal_pressure.nmap.PortScanner")
    def test_returns_dict_with_hosts(self, MockScanner, mock_scanner):
        MockScanner.return_value = mock_scanner
        result = scan_vulns("192.168.1.1")
        assert isinstance(result, dict)
        assert "target" in result
        assert "hosts" in result
        assert len(result["hosts"]) == 1

    @patch("terminal_pressure.nmap.PortScanner")
    def test_json_output_format(self, MockScanner, mock_scanner, capsys):
        MockScanner.return_value = mock_scanner
        result = scan_vulns("192.168.1.1", output_format=OUTPUT_FORMAT_JSON)
        captured = capsys.readouterr()
        assert '"target"' in captured.out
        assert '"192.168.1.1"' in captured.out


# ===========================================================================
# stress_test()
# ===========================================================================


class TestStressTest:
    @patch("terminal_pressure.socket.socket")
    def test_returns_result_dict(self, mock_socket_cls):
        result = stress_test("127.0.0.1", port=8080, threads=5, duration=1)
        assert isinstance(result, dict)
        assert result["target"] == "127.0.0.1"
        assert result["port"] == 8080
        assert result["threads"] == 5
        assert result["duration"] == 1

    @patch("terminal_pressure.socket.socket")
    def test_default_thread_count_in_result(self, mock_socket_cls):
        result = stress_test("127.0.0.1", duration=1)
        assert result["threads"] == DEFAULT_THREADS

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

        stress_test("127.0.0.1", port=80, threads=1, duration=1)
        # close() should have been called at least once
        assert mock_sock.close.called

    @patch("terminal_pressure.socket.socket")
    def test_connection_error_counted(self, mock_socket_cls):
        """OSError during connect should be counted as failed."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_sock

        result = stress_test("127.0.0.1", port=80, threads=2, duration=1)
        # All connections should have failed
        assert result["connections_failed"] > 0
        assert result["connections_succeeded"] == 0

    @patch("terminal_pressure.socket.socket")
    def test_successful_connection_counted(self, mock_socket_cls):
        """Successful connections should be counted."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        result = stress_test("127.0.0.1", port=80, threads=1, duration=1)
        # Some connections should have succeeded
        assert result["connections_attempted"] > 0

    @patch("terminal_pressure.socket.socket")
    def test_logs_start_message(self, mock_socket_cls, caplog):
        import logging

        with caplog.at_level(logging.INFO):
            stress_test("127.0.0.1", port=80, threads=2, duration=1)
        assert "Applying pressure" in caplog.text

    @patch("terminal_pressure.socket.socket")
    def test_logs_completion_message(self, mock_socket_cls, caplog):
        import logging

        with caplog.at_level(logging.INFO):
            stress_test("127.0.0.1", port=80, threads=2, duration=1)
        assert "complete" in caplog.text.lower()

    @patch("terminal_pressure.socket.socket")
    def test_json_output_format(self, mock_socket_cls, capsys):
        result = stress_test(
            "127.0.0.1", port=80, threads=2, duration=1, output_format=OUTPUT_FORMAT_JSON
        )
        captured = capsys.readouterr()
        assert '"target"' in captured.out
        assert '"127.0.0.1"' in captured.out

    def test_exceeds_max_threads_raises(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            stress_test("127.0.0.1", threads=MAX_THREADS + 1, duration=1)

    def test_exceeds_max_duration_raises(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            stress_test("127.0.0.1", threads=1, duration=MAX_DURATION + 1)


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

        result = exploit_chain("192.168.1.100")

        mock_ip.assert_called_once_with(dst="192.168.1.100")
        mock_tcp.assert_called_once_with(dport=EXPLOIT_PORT, flags="S")
        mock_raw.assert_called_once_with(load=EXPLOIT_MAGIC)
        mock_send.assert_called_once()
        assert result["status"] == "success"

    @patch("terminal_pressure.send")
    def test_custom_payload_does_not_send_packet(self, mock_send):
        result = exploit_chain("10.0.0.1", payload="my_custom_exploit")
        mock_send.assert_not_called()
        assert result["payload"] == "my_custom_exploit"
        assert result["status"] == "success"

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
            result = exploit_chain("  192.168.0.1  ")
            mock_ip.assert_called_once_with(dst="192.168.0.1")
            assert result["target"] == "192.168.0.1"

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_returns_dict(self, mock_ip, mock_tcp, mock_raw, mock_send):
        mock_ip.return_value = MagicMock()
        mock_tcp.return_value = MagicMock()
        mock_raw.return_value = MagicMock()

        result = exploit_chain("192.168.1.100")
        assert isinstance(result, dict)
        assert "target" in result
        assert "payload" in result
        assert "status" in result
        assert "message" in result

    @patch("terminal_pressure.send")
    @patch("terminal_pressure.Raw")
    @patch("terminal_pressure.TCP")
    @patch("terminal_pressure.IP")
    def test_json_output_format(self, mock_ip, mock_tcp, mock_raw, mock_send, capsys):
        mock_ip.return_value = MagicMock()
        mock_tcp.return_value = MagicMock()
        mock_raw.return_value = MagicMock()

        exploit_chain("192.168.1.100", output_format=OUTPUT_FORMAT_JSON)
        captured = capsys.readouterr()
        assert '"target"' in captured.out
        assert '"192.168.1.100"' in captured.out


# ===========================================================================
# main() – CLI dispatch
# ===========================================================================


class TestMain:
    @patch("terminal_pressure.scan_vulns")
    def test_scan_command_dispatches(self, mock_scan):
        with patch("sys.argv", ["tp", "scan", "192.168.1.1"]):
            main()
        mock_scan.assert_called_once_with("192.168.1.1", output_format=OUTPUT_FORMAT_TEXT)

    @patch("terminal_pressure.stress_test")
    def test_stress_command_dispatches_defaults(self, mock_stress):
        with patch("sys.argv", ["tp", "stress", "example.com"]):
            main()
        mock_stress.assert_called_once_with(
            "example.com", DEFAULT_PORT, DEFAULT_THREADS, DEFAULT_DURATION,
            output_format=OUTPUT_FORMAT_TEXT
        )

    @patch("terminal_pressure.stress_test")
    def test_stress_command_dispatches_custom_args(self, mock_stress):
        with patch(
            "sys.argv",
            ["tp", "stress", "example.com", "--port", "9090", "--threads", "10", "--duration", "5"],
        ):
            main()
        mock_stress.assert_called_once_with(
            "example.com", 9090, 10, 5, output_format=OUTPUT_FORMAT_TEXT
        )

    @patch("terminal_pressure.exploit_chain")
    def test_exploit_command_dispatches_default(self, mock_exploit):
        with patch("sys.argv", ["tp", "exploit", "10.0.0.1"]):
            main()
        mock_exploit.assert_called_once_with(
            "10.0.0.1", DEFAULT_PAYLOAD, output_format=OUTPUT_FORMAT_TEXT
        )

    @patch("terminal_pressure.exploit_chain")
    def test_exploit_command_dispatches_custom_payload(self, mock_exploit):
        with patch("sys.argv", ["tp", "exploit", "10.0.0.1", "--payload", "my_payload"]):
            main()
        mock_exploit.assert_called_once_with(
            "10.0.0.1", "my_payload", output_format=OUTPUT_FORMAT_TEXT
        )

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
        mock_scan.assert_called_once_with("my.host.local", output_format=OUTPUT_FORMAT_TEXT)

    @patch("terminal_pressure.scan_vulns")
    def test_json_output_format_flag(self, mock_scan):
        with patch("sys.argv", ["tp", "-f", "json", "scan", "192.168.1.1"]):
            main()
        mock_scan.assert_called_once_with("192.168.1.1", output_format=OUTPUT_FORMAT_JSON)

    @patch("terminal_pressure._configure_logging")
    @patch("terminal_pressure.scan_vulns")
    def test_verbose_flag(self, mock_scan, mock_configure):
        with patch("sys.argv", ["tp", "-v", "scan", "192.168.1.1"]):
            main()
        mock_configure.assert_called_once_with(verbose=True, quiet=False)

    @patch("terminal_pressure._configure_logging")
    @patch("terminal_pressure.scan_vulns")
    def test_quiet_flag(self, mock_scan, mock_configure):
        with patch("sys.argv", ["tp", "-q", "scan", "192.168.1.1"]):
            main()
        mock_configure.assert_called_once_with(verbose=False, quiet=True)

    def test_version_flag(self):
        with patch("sys.argv", ["tp", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0


# ===========================================================================
# _configure_logging tests
# ===========================================================================


class TestConfigureLogging:
    def test_verbose_sets_debug(self):
        import logging
        original_level = logging.getLogger().level
        try:
            _configure_logging(verbose=True)
            assert logging.getLogger().level == logging.DEBUG
        finally:
            logging.getLogger().setLevel(original_level)

    def test_quiet_sets_warning(self):
        import logging
        original_level = logging.getLogger().level
        try:
            _configure_logging(quiet=True)
            assert logging.getLogger().level == logging.WARNING
        finally:
            logging.getLogger().setLevel(original_level)

    def test_default_no_change(self):
        import logging
        original_level = logging.getLogger().level
        _configure_logging()
        # Level shouldn't change when no flags are set
        assert logging.getLogger().level == original_level


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

    def test_max_threads(self):
        assert MAX_THREADS == 1000

    def test_max_duration(self):
        assert MAX_DURATION == 3600

    def test_valid_output_formats(self):
        assert OUTPUT_FORMAT_TEXT in VALID_OUTPUT_FORMATS
        assert OUTPUT_FORMAT_JSON in VALID_OUTPUT_FORMATS

    def test_version_format(self):
        # Version should be a string like "1.0.0"
        assert isinstance(VERSION, str)
        parts = VERSION.split(".")
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)


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

        result = scan_vulns("10.0.0.0/30")
        assert len(result["hosts"]) == 2

    @patch("terminal_pressure.socket.socket")
    def test_stress_test_completes(self, mock_socket_cls):
        """stress_test should complete and return results."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        result = stress_test("127.0.0.1", port=80, threads=5, duration=1)
        assert result["connections_attempted"] >= 0

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

        scan_result = scan_vulns("192.168.0.1")
        mock_ip.return_value = MagicMock()
        exploit_result = exploit_chain("192.168.0.1")

        mock_send.assert_called_once()
        assert scan_result["target"] == "192.168.0.1"
        assert exploit_result["target"] == "192.168.0.1"
