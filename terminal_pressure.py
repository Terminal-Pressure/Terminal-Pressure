#!/usr/bin/env python3
"""
Terminal Pressure - Security Testing Toolkit
============================================
LEGAL DISCLAIMER: This tool is intended for authorized security testing and
educational purposes ONLY. Use only on systems you own or have explicit written
permission to test. Unauthorized use is illegal and unethical. The authors
accept no liability for misuse.

Usage:
    python terminal_pressure.py scan <target>
    python terminal_pressure.py stress <target> [--port PORT] [--threads N] [--duration SECS]
    python terminal_pressure.py exploit <target> [--payload PAYLOAD]
"""

import argparse
import logging
import socket
import threading
import time
from typing import Optional

# External dependencies (pip install python-nmap scapy)
import nmap
from scapy.all import IP, TCP, Raw, send  # type: ignore[import]

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
# Input validation helpers
# ---------------------------------------------------------------------------

def _validate_target(target: str) -> str:
    """Validate and return the target string.

    Performs a basic sanity check to ensure the target is a non-empty string.
    DNS resolution failures are handled at call-time rather than here so that
    individual functions can provide context-specific error messages.

    Args:
        target: IP address or hostname to validate.

    Returns:
        The stripped target string.

    Raises:
        ValueError: If *target* is empty or not a string.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty string.")
    return target.strip()


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
    """Validate that the thread count is positive.

    Args:
        threads: Number of threads to validate.

    Returns:
        The validated thread count.

    Raises:
        ValueError: If *threads* is less than 1.
    """
    if not isinstance(threads, int) or threads < 1:
        raise ValueError(f"Thread count must be a positive integer, got {threads!r}.")
    return threads


def _validate_duration(duration: int) -> int:
    """Validate that the duration is positive.

    Args:
        duration: Duration in seconds to validate.

    Returns:
        The validated duration.

    Raises:
        ValueError: If *duration* is less than 1.
    """
    if not isinstance(duration, int) or duration < 1:
        raise ValueError(f"Duration must be a positive integer (seconds), got {duration!r}.")
    return duration


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def scan_vulns(target: str) -> None:
    """Perform a vulnerability scan against *target* using nmap.

    Runs an nmap service-version detection scan with the built-in vuln NSE
    scripts against ports 1–1024 and prints discovered open ports together
    with any vulnerability script output.

    WARNING: Only scan targets you own or have explicit written permission to
    test. Unauthorised port scanning may be illegal in your jurisdiction.

    Args:
        target: IP address or hostname of the scan target.

    Raises:
        ValueError: If *target* fails basic validation.
        nmap.PortScannerError: If nmap is not installed or the scan fails.
        Exception: Re-raised after logging for any unexpected scanner error.

    Examples:
        >>> scan_vulns("127.0.0.1")  # doctest: +SKIP
    """
    target = _validate_target(target)
    logger.info("Starting vulnerability scan on target: %s", target)

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, PORT_SCAN_RANGE, "-sV --script vuln")
    except nmap.PortScannerError as exc:
        logger.error("nmap scanner error: %s", exc)
        raise
    except Exception as exc:  # pragma: no cover – unexpected OS-level errors
        logger.error("Unexpected error during nmap scan: %s", exc)
        raise

    hosts = scanner.all_hosts()
    if not hosts:
        logger.info("No hosts found for target: %s", target)
        return

    for host in hosts:
        logger.info("Host: %s", host)
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                state = port_info.get("state", "unknown")
                service = port_info.get("name", "unknown")
                logger.info("  Port %s/%s: %s (%s)", port, proto, state, service)
                if "script" in port_info:
                    for script_name, script_output in port_info["script"].items():
                        logger.info("  Vuln Script: %s - %s", script_name, script_output)


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


def exploit_chain(target: str, payload: str = DEFAULT_PAYLOAD) -> None:
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

    Raises:
        ValueError: If *target* fails basic validation.
        Exception: Re-raised after logging for unexpected Scapy errors.

    Examples:
        >>> exploit_chain("127.0.0.1")  # doctest: +SKIP
    """
    target = _validate_target(target)

    if payload == DEFAULT_PAYLOAD:
        logger.info("Injecting backdoor sim on %s (authorised pentest simulation)", target)
        try:
            pkt = IP(dst=target) / TCP(dport=EXPLOIT_PORT, flags="S") / Raw(load=EXPLOIT_MAGIC)
            send(pkt, verbose=0)
        except Exception as exc:
            logger.error("Error during exploit simulation: %s", exc)
            raise
    else:
        logger.info("Custom exploit chain: %s on %s", payload, target)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate function.

    Sub-commands:
        scan    – vulnerability scan via nmap.
        stress  – connection-flood stress test.
        exploit – exploit-chain simulation.

    If no sub-command is provided, the help text is printed.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Terminal Pressure: Cyber Tool for Pressure Testing\n"
            "WARNING: Use only on systems you own or have written permission to test."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- scan sub-command
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilities")
    scan_parser.add_argument("target", type=str, help="Target IP/hostname")

    # -- stress sub-command
    stress_parser = subparsers.add_parser("stress", help="Stress test (DDoS sim)")
    stress_parser.add_argument("target", type=str, help="Target IP/hostname")
    stress_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port")
    stress_parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Threads")
    stress_parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION, help="Duration in seconds"
    )

    # -- exploit sub-command
    exploit_parser = subparsers.add_parser("exploit", help="Exploit chain (advanced)")
    exploit_parser.add_argument("target", type=str, help="Target IP/hostname")
    exploit_parser.add_argument(
        "--payload", type=str, default=DEFAULT_PAYLOAD, help="Payload type"
    )

    args = parser.parse_args()

    if args.command == "scan":
        scan_vulns(args.target)
    elif args.command == "stress":
        stress_test(args.target, args.port, args.threads, args.duration)
    elif args.command == "exploit":
        exploit_chain(args.target, args.payload)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
