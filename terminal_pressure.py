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

Environment Variables:
    TP_LOG_LEVEL: Set logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
"""

import argparse
import json
import logging
import os
import socket
import sys
import threading
import time
from typing import Any, Optional

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

# Safety limits
MAX_THREADS: int = 1000
MAX_DURATION: int = 3600  # 1 hour max

# Output format options
OUTPUT_FORMAT_TEXT: str = "text"
OUTPUT_FORMAT_JSON: str = "json"
VALID_OUTPUT_FORMATS: tuple[str, ...] = (OUTPUT_FORMAT_TEXT, OUTPUT_FORMAT_JSON)

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
_log_level = os.environ.get("TP_LOG_LEVEL", "INFO").upper()
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
    """Validate that the thread count is positive and within safety limits.

    Args:
        threads: Number of threads to validate.

    Returns:
        The validated thread count.

    Raises:
        ValueError: If *threads* is less than 1 or exceeds MAX_THREADS.
    """
    if not isinstance(threads, int) or threads < 1:
        raise ValueError(f"Thread count must be a positive integer, got {threads!r}.")
    if threads > MAX_THREADS:
        raise ValueError(f"Thread count {threads} exceeds maximum allowed ({MAX_THREADS}).")
    return threads


def _validate_duration(duration: int) -> int:
    """Validate that the duration is positive and within safety limits.

    Args:
        duration: Duration in seconds to validate.

    Returns:
        The validated duration.

    Raises:
        ValueError: If *duration* is less than 1 or exceeds MAX_DURATION.
    """
    if not isinstance(duration, int) or duration < 1:
        raise ValueError(f"Duration must be a positive integer (seconds), got {duration!r}.")
    if duration > MAX_DURATION:
        raise ValueError(f"Duration {duration}s exceeds maximum allowed ({MAX_DURATION}s).")
    return duration


def _validate_output_format(output_format: str) -> str:
    """Validate that the output format is supported.

    Args:
        output_format: Output format string to validate.

    Returns:
        The validated output format string.

    Raises:
        ValueError: If *output_format* is not in VALID_OUTPUT_FORMATS.
    """
    if output_format not in VALID_OUTPUT_FORMATS:
        raise ValueError(
            f"Invalid output format {output_format!r}. "
            f"Valid options: {', '.join(VALID_OUTPUT_FORMATS)}"
        )
    return output_format


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def scan_vulns(target: str, output_format: str = OUTPUT_FORMAT_TEXT) -> dict[str, Any]:
    """Perform a vulnerability scan against *target* using nmap.

    Runs an nmap service-version detection scan with the built-in vuln NSE
    scripts against ports 1–1024 and prints discovered open ports together
    with any vulnerability script output.

    WARNING: Only scan targets you own or have explicit written permission to
    test. Unauthorised port scanning may be illegal in your jurisdiction.

    Args:
        target: IP address or hostname of the scan target.
        output_format: Output format ('text' or 'json'). Default: 'text'.

    Returns:
        A dictionary containing scan results with keys:
        - 'target': The scanned target
        - 'hosts': List of discovered hosts with port/vuln info

    Raises:
        ValueError: If *target* fails basic validation.
        nmap.PortScannerError: If nmap is not installed or the scan fails.
        Exception: Re-raised after logging for any unexpected scanner error.

    Examples:
        >>> scan_vulns("127.0.0.1")  # doctest: +SKIP
        >>> scan_vulns("127.0.0.1", output_format="json")  # doctest: +SKIP
    """
    target = _validate_target(target)
    output_format = _validate_output_format(output_format)
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

    result: dict[str, Any] = {"target": target, "hosts": []}
    hosts = scanner.all_hosts()

    if not hosts:
        logger.info("No hosts found for target: %s", target)
        if output_format == OUTPUT_FORMAT_JSON:
            print(json.dumps(result, indent=2))
        return result

    for host in hosts:
        host_data: dict[str, Any] = {"host": host, "protocols": []}
        if output_format == OUTPUT_FORMAT_TEXT:
            logger.info("Host: %s", host)

        for proto in scanner[host].all_protocols():
            proto_data: dict[str, Any] = {"protocol": proto, "ports": []}
            ports = scanner[host][proto].keys()

            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                state = port_info.get("state", "unknown")
                service = port_info.get("name", "unknown")
                port_data: dict[str, Any] = {
                    "port": port,
                    "state": state,
                    "service": service,
                    "scripts": {},
                }

                if output_format == OUTPUT_FORMAT_TEXT:
                    logger.info("  Port %s/%s: %s (%s)", port, proto, state, service)

                if "script" in port_info:
                    for script_name, script_output in port_info["script"].items():
                        port_data["scripts"][script_name] = script_output
                        if output_format == OUTPUT_FORMAT_TEXT:
                            logger.info("  Vuln Script: %s - %s", script_name, script_output)

                proto_data["ports"].append(port_data)
            host_data["protocols"].append(proto_data)
        result["hosts"].append(host_data)

    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))

    return result


def stress_test(
    target: str,
    port: int = DEFAULT_PORT,
    threads: int = DEFAULT_THREADS,
    duration: int = DEFAULT_DURATION,
    output_format: str = OUTPUT_FORMAT_TEXT,
) -> dict[str, Any]:
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
        threads: Number of concurrent worker threads (default: 50, max: 1000).
        duration: How long (in seconds) each worker thread floods (default: 60, max: 3600).
        output_format: Output format ('text' or 'json'). Default: 'text'.

    Returns:
        A dictionary containing stress test results with keys:
        - 'target': The target host
        - 'port': The target port
        - 'threads': Number of threads used
        - 'duration': Duration in seconds
        - 'connections_attempted': Total connection attempts
        - 'connections_succeeded': Successful connections
        - 'connections_failed': Failed connections

    Raises:
        ValueError: If any argument fails basic validation.

    Examples:
        >>> result = stress_test("127.0.0.1", port=8080, threads=2, duration=1)
        >>> print(result['connections_attempted'])  # doctest: +SKIP
    """
    target = _validate_target(target)
    port = _validate_port(port)
    threads = _validate_threads(threads)
    duration = _validate_duration(duration)
    output_format = _validate_output_format(output_format)

    logger.info(
        "Applying pressure to %s:%d with %d threads for %ds", target, port, threads, duration
    )

    # Thread-safe counters
    stats_lock = threading.Lock()
    stats = {"attempted": 0, "succeeded": 0, "failed": 0}

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
                with stats_lock:
                    stats["attempted"] += 1
                    stats["succeeded"] += 1
            except OSError:
                # Connection refused / timeout / DNS failure – keep going
                with stats_lock:
                    stats["attempted"] += 1
                    stats["failed"] += 1
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

    # Wait for all threads to complete
    for t in started:
        t.join()

    result: dict[str, Any] = {
        "target": target,
        "port": port,
        "threads": threads,
        "duration": duration,
        "connections_attempted": stats["attempted"],
        "connections_succeeded": stats["succeeded"],
        "connections_failed": stats["failed"],
    }

    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))
    else:
        logger.info(
            "Stress test complete: %d attempts, %d succeeded, %d failed",
            stats["attempted"],
            stats["succeeded"],
            stats["failed"],
        )

    return result


def exploit_chain(
    target: str,
    payload: str = DEFAULT_PAYLOAD,
    output_format: str = OUTPUT_FORMAT_TEXT,
) -> dict[str, Any]:
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
        output_format: Output format ('text' or 'json'). Default: 'text'.

    Returns:
        A dictionary containing exploit results with keys:
        - 'target': The target host
        - 'payload': The payload identifier
        - 'status': 'success' or 'error'
        - 'message': Status message

    Raises:
        ValueError: If *target* fails basic validation.
        Exception: Re-raised after logging for unexpected Scapy errors.

    Examples:
        >>> exploit_chain("127.0.0.1")  # doctest: +SKIP
    """
    target = _validate_target(target)
    output_format = _validate_output_format(output_format)

    result: dict[str, Any] = {
        "target": target,
        "payload": payload,
        "status": "success",
        "message": "",
    }

    if payload == DEFAULT_PAYLOAD:
        logger.info("Injecting backdoor sim on %s (authorised pentest simulation)", target)
        try:
            pkt = IP(dst=target) / TCP(dport=EXPLOIT_PORT, flags="S") / Raw(load=EXPLOIT_MAGIC)
            send(pkt, verbose=0)
            result["message"] = f"Backdoor simulation sent to {target}:{EXPLOIT_PORT}"
        except Exception as exc:
            logger.error("Error during exploit simulation: %s", exc)
            result["status"] = "error"
            result["message"] = str(exc)
            raise
    else:
        logger.info("Custom exploit chain: %s on %s", payload, target)
        result["message"] = f"Custom exploit chain '{payload}' executed on {target}"

    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging based on verbosity flags.

    Args:
        verbose: If True, set log level to DEBUG.
        quiet: If True, set log level to WARNING.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)


def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate function.

    Sub-commands:
        scan    – vulnerability scan via nmap.
        stress  – connection-flood stress test.
        exploit – exploit-chain simulation.

    Global flags:
        --verbose, -v : Enable debug logging.
        --quiet, -q   : Suppress info messages, only show warnings/errors.
        --output-format, -f : Output format ('text' or 'json').

    If no sub-command is provided, the help text is printed.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Terminal Pressure: Cyber Tool for Pressure Testing\n"
            "WARNING: Use only on systems you own or have written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global arguments
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose (debug) output"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress info messages"
    )
    parser.add_argument(
        "-f",
        "--output-format",
        type=str,
        choices=VALID_OUTPUT_FORMATS,
        default=OUTPUT_FORMAT_TEXT,
        help="Output format (default: text)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # -- scan sub-command
    scan_parser = subparsers.add_parser("scan", help="Scan for vulnerabilities")
    scan_parser.add_argument("target", type=str, help="Target IP/hostname")

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

    # Configure logging based on flags
    _configure_logging(verbose=args.verbose, quiet=args.quiet)

    if args.command == "scan":
        scan_vulns(args.target, output_format=args.output_format)
    elif args.command == "stress":
        stress_test(
            args.target,
            args.port,
            args.threads,
            args.duration,
            output_format=args.output_format,
        )
    elif args.command == "exploit":
        exploit_chain(args.target, args.payload, output_format=args.output_format)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
