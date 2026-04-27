#!/usr/bin/env python3
"""
Terminal Pressure - Security Testing Toolkit
============================================
LEGAL DISCLAIMER: This tool is intended for authorized security testing and
educational purposes ONLY. Use only on systems you own or have explicit written
permission to test. Unauthorized use is illegal and unethical. The authors
accept no liability for misuse.

Usage:
    python terminal_pressure.py scan <target> [--format json|csv|text]
    python terminal_pressure.py stress <target> [--port PORT] [--threads N] [--duration SECS]
    python terminal_pressure.py exploit <target> [--payload PAYLOAD]
    python terminal_pressure.py version
"""

import argparse
import csv
import io
import ipaddress
import json
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# External dependencies (pip install python-nmap scapy)
import nmap
from scapy.all import IP, TCP, Raw, send  # type: ignore[import]

# ---------------------------------------------------------------------------
# Version Info
# ---------------------------------------------------------------------------
__version__ = "2.0.0"
__author__ = "Terminal Pressure Labs"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PORT: int = 80
DEFAULT_THREADS: int = 50
DEFAULT_DURATION: int = 60
DEFAULT_PAYLOAD: str = "default_backdoor"
SOCKET_TIMEOUT: float = 5.0
PORT_SCAN_RANGE: str = "1-1024"
EXPLOIT_PORT: int = 4444
EXPLOIT_MAGIC: bytes = b"CHAOS_AWAKEN"
MAX_THREADS: int = 500
MAX_DURATION: int = 3600
DNS_TIMEOUT: float = 5.0

# Output format options
OUTPUT_TEXT: str = "text"
OUTPUT_JSON: str = "json"
OUTPUT_CSV: str = "csv"

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
import os as _os

_log_level = _os.environ.get("TP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes for structured results
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    protocol: str
    state: str
    service: str
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    """Result of scanning a single host."""
    host: str
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    hosts: list[HostResult] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        """Convert to CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "port", "protocol", "state", "service", "scripts"])
        for host_result in self.hosts:
            for port_result in host_result.ports:
                scripts_str = "; ".join(
                    f"{k}: {v}" for k, v in port_result.scripts.items()
                )
                writer.writerow([
                    host_result.host,
                    port_result.port,
                    port_result.protocol,
                    port_result.state,
                    port_result.service,
                    scripts_str,
                ])
        return output.getvalue()


@dataclass
class StressResult:
    """Result of stress test."""
    target: str
    port: int
    threads: int
    duration: int
    started: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class ExploitResult:
    """Result of exploit chain execution."""
    target: str
    payload: str
    sent: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def _is_valid_ip(target: str) -> bool:
    """Check if target is a valid IP address.

    Args:
        target: String to check.

    Returns:
        True if target is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_valid_cidr(target: str) -> bool:
    """Check if target is a valid CIDR notation.

    Args:
        target: String to check.

    Returns:
        True if target is a valid CIDR network notation.
    """
    try:
        ipaddress.ip_network(target, strict=False)
        return "/" in target  # Must have / to be CIDR
    except ValueError:
        return False


def _is_valid_hostname(hostname: str) -> bool:
    """Check if hostname follows valid hostname format.

    Args:
        hostname: String to check.

    Returns:
        True if hostname appears to be a valid hostname format.
    """
    if not hostname or len(hostname) > 253:
        return False
    # RFC 1123 hostname pattern:
    # - Labels are 1-63 alphanumeric/hyphen characters
    # - Labels cannot start or end with a hyphen
    # - Labels are separated by dots
    # - Trailing dot is optional (for FQDN)
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
    return bool(re.match(pattern, hostname))


def _resolve_hostname(hostname: str, timeout: float = DNS_TIMEOUT) -> Optional[str]:
    """Resolve hostname to IP address.

    Args:
        hostname: Hostname to resolve.
        timeout: DNS lookup timeout in seconds.

    Returns:
        Resolved IP address or None if resolution fails.
    """
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
    finally:
        socket.setdefaulttimeout(None)


# Maximum hosts to scan from CIDR to prevent memory/performance issues
# and avoid accidental large network scans (e.g., /8 or /16 networks)
MAX_CIDR_HOSTS: int = 256


def _expand_cidr(cidr: str) -> list[str]:
    """Expand CIDR notation to list of individual IP addresses.

    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24").

    Returns:
        List of individual IP address strings.

    Note:
        For large networks (> MAX_CIDR_HOSTS hosts), returns only the first
        MAX_CIDR_HOSTS to prevent resource exhaustion and accidental scans
        of very large networks.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > MAX_CIDR_HOSTS:
            logger.warning(
                "CIDR %s contains %d hosts; limiting to first %d",
                cidr,
                len(hosts),
                MAX_CIDR_HOSTS,
            )
            hosts = hosts[:MAX_CIDR_HOSTS]
        return [str(ip) for ip in hosts]
    except ValueError:
        return []


def _validate_target(target: str) -> str:
    """Validate and return the target string.

    Performs a basic sanity check to ensure the target is a non-empty string.
    Validates IP address, CIDR notation, or hostname format.

    Args:
        target: IP address, CIDR notation, or hostname to validate.

    Returns:
        The stripped target string.

    Raises:
        ValueError: If *target* is empty, not a string, or invalid format.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty string.")

    target = target.strip()

    # Check if it's a valid IP, CIDR, or hostname
    if not (_is_valid_ip(target) or _is_valid_cidr(target) or _is_valid_hostname(target)):
        raise ValueError(
            f"Target must be a valid IP address, CIDR notation, or hostname, got {target!r}."
        )

    return target


def _validate_port(port: int) -> int:
    """Validate that *port* is within the valid TCP/UDP range.

    Args:
        port: Port number to validate.

    Returns:
        The validated port number.

    Raises:
        ValueError: If *port* is outside [1, 65535].
    """
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be an integer between 1 and 65535, got {port!r}.")
    return port


def _validate_threads(threads: int) -> int:
    """Validate that the thread count is positive and within bounds.

    Args:
        threads: Number of threads to validate.

    Returns:
        The validated thread count.

    Raises:
        ValueError: If *threads* is less than 1 or greater than MAX_THREADS.
    """
    if not isinstance(threads, int) or threads < 1:
        raise ValueError(f"Thread count must be a positive integer, got {threads!r}.")
    if threads > MAX_THREADS:
        raise ValueError(f"Thread count cannot exceed {MAX_THREADS}, got {threads}.")
    return threads


def _validate_duration(duration: int) -> int:
    """Validate that the duration is positive and within bounds.

    Args:
        duration: Duration in seconds to validate.

    Returns:
        The validated duration.

    Raises:
        ValueError: If *duration* is less than 1.
    """
    if not isinstance(duration, int) or duration < 1:
        raise ValueError(f"Duration must be a positive integer (seconds), got {duration!r}.")
    if duration > MAX_DURATION:
        raise ValueError(f"Duration cannot exceed {MAX_DURATION} seconds, got {duration}.")
    return duration


def _validate_output_format(fmt: str) -> str:
    """Validate output format option.

    Args:
        fmt: Output format string.

    Returns:
        Validated format string.

    Raises:
        ValueError: If format is not one of: text, json, csv.
    """
    valid_formats = [OUTPUT_TEXT, OUTPUT_JSON, OUTPUT_CSV]
    if fmt not in valid_formats:
        raise ValueError(f"Output format must be one of {valid_formats}, got {fmt!r}.")
    return fmt


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def scan_vulns(target: str, output_format: str = OUTPUT_TEXT) -> ScanResult:
    """Perform a vulnerability scan against *target* using nmap.

    Runs an nmap service-version detection scan with the built-in vuln NSE
    scripts against ports 1–1024 and returns structured results. Also logs
    discovered open ports together with any vulnerability script output.

    WARNING: Only scan targets you own or have explicit written permission to
    test. Unauthorised port scanning may be illegal in your jurisdiction.

    Args:
        target: IP address, CIDR notation, or hostname of the scan target.
        output_format: Output format ("text", "json", or "csv").

    Returns:
        ScanResult object containing all discovered hosts, ports, and vulns.

    Raises:
        ValueError: If *target* or *output_format* fails basic validation.
        nmap.PortScannerError: If nmap is not installed or the scan fails.
        Exception: Re-raised after logging for any unexpected scanner error.

    Examples:
        >>> result = scan_vulns("127.0.0.1")  # doctest: +SKIP
        >>> result = scan_vulns("192.168.1.0/24", output_format="json")  # doctest: +SKIP
    """
    target = _validate_target(target)
    output_format = _validate_output_format(output_format)

    logger.info("Starting vulnerability scan on target: %s", target)
    start_time = time.time()

    result = ScanResult(target=target)

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, PORT_SCAN_RANGE, "-sV --script vuln")
    except nmap.PortScannerError as exc:
        logger.error("nmap scanner error: %s", exc)
        result.error = str(exc)
        raise
    except Exception as exc:  # pragma: no cover – unexpected OS-level errors
        logger.error("Unexpected error during nmap scan: %s", exc)
        result.error = str(exc)
        raise

    result.scan_time = time.time() - start_time

    hosts = scanner.all_hosts()
    if not hosts:
        logger.info("No hosts found for target: %s", target)
        _output_scan_result(result, output_format)
        return result

    for host in hosts:
        host_result = HostResult(host=host)
        logger.info("Host: %s", host)

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                state = port_info.get("state", "unknown")
                service = port_info.get("name", "unknown")
                scripts = port_info.get("script", {})

                port_result = PortResult(
                    port=port,
                    protocol=proto,
                    state=state,
                    service=service,
                    scripts=scripts,
                )
                host_result.ports.append(port_result)

                logger.info("  Port %s/%s: %s (%s)", port, proto, state, service)
                for script_name, script_output in scripts.items():
                    logger.info("  Vuln Script: %s - %s", script_name, script_output)

        result.hosts.append(host_result)

    _output_scan_result(result, output_format)
    return result


def _output_scan_result(result: ScanResult, output_format: str) -> None:
    """Output scan result in the specified format.

    Args:
        result: ScanResult to output.
        output_format: Output format (text, json, csv).
    """
    if output_format == OUTPUT_JSON:
        print(result.to_json())
    elif output_format == OUTPUT_CSV:
        print(result.to_csv())
    # Text format is already logged above


def stress_test(
    target: str,
    port: int = DEFAULT_PORT,
    threads: int = DEFAULT_THREADS,
    duration: int = DEFAULT_DURATION,
) -> list[threading.Thread]:
    """Simulate a connection-flood stress test against *target*:*port*.

    Spawns *threads* worker threads, each of which repeatedly opens a TCP
    connection to ``target:port``, sends a minimal HTTP GET request, and
    closes the socket until *duration* seconds have elapsed.

    WARNING: Only run stress tests against infrastructure you own or have
    explicit written permission to test. Unauthorised load testing is illegal
    and unethical.

    Args:
        target: IP address or hostname of the target.
        port: TCP port to connect to (default: 80).
        threads: Number of concurrent worker threads (default: 50).
        duration: How long (in seconds) each worker thread floods (default: 60).

    Returns:
        A list of started :class:`threading.Thread` objects so callers can
        join/monitor them if desired.

    Raises:
        ValueError: If any argument fails basic validation.

    Examples:
        >>> worker_threads = stress_test("127.0.0.1", port=8080, threads=2, duration=1)
        >>> for t in worker_threads: t.join()  # doctest: +SKIP
    """
    target = _validate_target(target)
    port = _validate_port(port)
    threads = _validate_threads(threads)
    duration = _validate_duration(duration)

    logger.info(
        "Applying pressure to %s:%d with %d threads for %ds", target, port, threads, duration
    )

    def flood() -> None:
        """Inner worker: open, send, close in a tight loop until time is up."""
        end_time = time.time() + duration
        while time.time() < end_time:
            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect((target, port))
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            except OSError:
                # Connection refused / timeout / DNS failure – keep going
                pass
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    started: list[threading.Thread] = []
    for _ in range(threads):
        t = threading.Thread(target=flood, daemon=True)
        t.start()
        started.append(t)

    return started


def exploit_chain(target: str, payload: str = DEFAULT_PAYLOAD) -> ExploitResult:
    """Simulate an exploit delivery chain against *target*.

    For the ``default_backdoor`` payload this crafts a SYN packet to port
    4444 using Scapy (simulation only – no real shellcode is embedded).  Any
    other payload string is treated as a custom chain identifier and only
    logged.

    WARNING: Only use against targets you own or have explicit written
    permission to test. This function is a *simulation*; replace the Scapy
    payload with your authorised pentest tooling as required.

    Args:
        target: IP address or hostname of the target.
        payload: Payload identifier (default: ``"default_backdoor"``).

    Returns:
        ExploitResult object containing execution status.

    Raises:
        ValueError: If *target* fails basic validation.
        Exception: Re-raised after logging for unexpected Scapy errors.

    Examples:
        >>> result = exploit_chain("127.0.0.1")  # doctest: +SKIP
    """
    target = _validate_target(target)
    result = ExploitResult(target=target, payload=payload)

    if payload == DEFAULT_PAYLOAD:
        logger.info("Injecting backdoor sim on %s (authorised pentest simulation)", target)
        try:
            pkt = IP(dst=target) / TCP(dport=EXPLOIT_PORT, flags="S") / Raw(load=EXPLOIT_MAGIC)
            send(pkt, verbose=0)
            result.sent = True
        except Exception as exc:
            logger.error("Error during exploit simulation: %s", exc)
            result.error = str(exc)
            raise
    else:
        logger.info("Custom exploit chain: %s on %s", payload, target)
        result.sent = False  # Custom payloads not sent in simulation mode

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate function.

    Sub-commands:
        scan    – vulnerability scan via nmap.
        stress  – connection-flood stress test.
        exploit – exploit-chain simulation.
        version – display version information.

    If no sub-command is provided, the help text is printed.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Terminal Pressure: Cyber Tool for Pressure Testing\n"
            "WARNING: Use only on systems you own or have written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- version sub-command
    subparsers.add_parser("version", help="Display version information")

    # -- scan sub-command
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilities")
    scan_parser.add_argument("target", type=str, help="Target IP/hostname/CIDR")
    scan_parser.add_argument(
        "--format",
        type=str,
        default=OUTPUT_TEXT,
        choices=[OUTPUT_TEXT, OUTPUT_JSON, OUTPUT_CSV],
        help="Output format (default: text)",
    )

    # -- stress sub-command
    stress_parser = subparsers.add_parser("stress", help="Stress test (DDoS sim)")
    stress_parser.add_argument("target", type=str, help="Target IP/hostname")
    stress_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port")
    stress_parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Threads (max: {MAX_THREADS})",
    )
    stress_parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help=f"Duration in seconds (max: {MAX_DURATION})",
    )

    # -- exploit sub-command
    exploit_parser = subparsers.add_parser("exploit", help="Exploit chain (advanced)")
    exploit_parser.add_argument("target", type=str, help="Target IP/hostname")
    exploit_parser.add_argument(
        "--payload", type=str, default=DEFAULT_PAYLOAD, help="Payload type"
    )

    args = parser.parse_args()

    if args.command == "version":
        print(f"Terminal Pressure v{__version__}")
        print(f"Author: {__author__}")
    elif args.command == "scan":
        scan_vulns(args.target, output_format=args.format)
    elif args.command == "stress":
        stress_test(args.target, args.port, args.threads, args.duration)
    elif args.command == "exploit":
        exploit_chain(args.target, args.payload)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
