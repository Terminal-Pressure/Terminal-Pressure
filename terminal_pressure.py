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
import csv
import io
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
VERSION: str = "1.0.0"
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
MIN_TIMEOUT: float = 0.1
MAX_TIMEOUT: float = 300.0  # 5 minutes max
DEFAULT_RETRIES: int = 0
MAX_RETRIES: int = 10

# Output format options
OUTPUT_FORMAT_TEXT: str = "text"
OUTPUT_FORMAT_JSON: str = "json"
OUTPUT_FORMAT_CSV: str = "csv"
VALID_OUTPUT_FORMATS: tuple[str, ...] = (OUTPUT_FORMAT_TEXT, OUTPUT_FORMAT_JSON, OUTPUT_FORMAT_CSV)

# Exit codes
EXIT_SUCCESS: int = 0
EXIT_ERROR: int = 1
EXIT_VALIDATION_ERROR: int = 2

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


def _validate_timeout(timeout: float) -> float:
    """Validate that the timeout is within acceptable limits.

    Args:
        timeout: Timeout value in seconds.

    Returns:
        The validated timeout value.

    Raises:
        ValueError: If *timeout* is outside [MIN_TIMEOUT, MAX_TIMEOUT].
    """
    if not isinstance(timeout, (int, float)) or timeout < MIN_TIMEOUT:
        raise ValueError(f"Timeout must be at least {MIN_TIMEOUT} seconds, got {timeout!r}.")
    if timeout > MAX_TIMEOUT:
        raise ValueError(f"Timeout {timeout}s exceeds maximum allowed ({MAX_TIMEOUT}s).")
    return float(timeout)


def _validate_retries(retries: int) -> int:
    """Validate that the retry count is within acceptable limits.

    Args:
        retries: Number of retries.

    Returns:
        The validated retry count.

    Raises:
        ValueError: If *retries* is negative or exceeds MAX_RETRIES.
    """
    if not isinstance(retries, int) or retries < 0:
        raise ValueError(f"Retries must be a non-negative integer, got {retries!r}.")
    if retries > MAX_RETRIES:
        raise ValueError(f"Retries {retries} exceeds maximum allowed ({MAX_RETRIES}).")
    return retries


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
        output_format: Output format ('text', 'json', or 'csv'). Default: 'text'.

    Returns:
        A dictionary containing scan results with keys:
        - 'target': The scanned target
        - 'hosts': List of discovered hosts with port/vuln info
        - 'scan_time_seconds': Duration of the scan

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

    start_time = time.time()

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, PORT_SCAN_RANGE, "-sV --script vuln")
    except nmap.PortScannerError as exc:
        logger.error("nmap scanner error: %s", exc)
        raise
    except Exception as exc:  # pragma: no cover – unexpected OS-level errors
        logger.error("Unexpected error during nmap scan: %s", exc)
        raise

    scan_time = time.time() - start_time
    result: dict[str, Any] = {"target": target, "hosts": [], "scan_time_seconds": round(scan_time, 2)}
    hosts = scanner.all_hosts()

    if not hosts:
        logger.info("No hosts found for target: %s", target)
        _output_scan_result(result, output_format)
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

    _output_scan_result(result, output_format)
    return result


def _output_scan_result(result: dict[str, Any], output_format: str) -> None:
    """Output scan results in the specified format.

    Args:
        result: The scan result dictionary.
        output_format: Output format ('text', 'json', or 'csv').
    """
    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))
    elif output_format == OUTPUT_FORMAT_CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "protocol", "port", "state", "service", "scripts"])
        for host_data in result.get("hosts", []):
            host = host_data.get("host", "")
            for proto_data in host_data.get("protocols", []):
                proto = proto_data.get("protocol", "")
                for port_data in proto_data.get("ports", []):
                    scripts_str = ";".join(
                        f"{k}={v}" for k, v in port_data.get("scripts", {}).items()
                    )
                    writer.writerow([
                        host,
                        proto,
                        port_data.get("port", ""),
                        port_data.get("state", ""),
                        port_data.get("service", ""),
                        scripts_str,
                    ])
        print(output.getvalue().strip())


def stress_test(
    target: str,
    port: int = DEFAULT_PORT,
    threads: int = DEFAULT_THREADS,
    duration: int = DEFAULT_DURATION,
    output_format: str = OUTPUT_FORMAT_TEXT,
    timeout: float = SOCKET_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
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
        output_format: Output format ('text', 'json', or 'csv'). Default: 'text'.
        timeout: Socket timeout in seconds (default: 5.0, range: 0.1-300).
        retries: Number of retries for failed connections (default: 0, max: 10).

    Returns:
        A dictionary containing stress test results with keys:
        - 'target': The target host
        - 'port': The target port
        - 'threads': Number of threads used
        - 'duration': Duration in seconds
        - 'timeout': Socket timeout used
        - 'retries': Number of retries configured
        - 'actual_duration_seconds': Actual elapsed time
        - 'connections_attempted': Total connection attempts
        - 'connections_succeeded': Successful connections
        - 'connections_failed': Failed connections
        - 'connections_retried': Total retry attempts
        - 'connections_per_second': Average connections per second

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
    timeout = _validate_timeout(timeout)
    retries = _validate_retries(retries)

    logger.info(
        "Applying pressure to %s:%d with %d threads for %ds (timeout=%.1fs, retries=%d)",
        target, port, threads, duration, timeout, retries
    )

    start_time = time.time()

    # Thread-safe counters
    stats_lock = threading.Lock()
    stats = {"attempted": 0, "succeeded": 0, "failed": 0, "retried": 0}

    def flood() -> None:
        """Inner worker: open, send, close in a tight loop until time is up."""
        end_time = time.time() + duration
        while time.time() < end_time:
            remaining_attempts = retries + 1  # Initial attempt + retries
            attempt_number = 0
            success = False
            current_time = time.time()

            while remaining_attempts > 0 and not success and current_time < end_time:
                attempt_number += 1
                sock: Optional[socket.socket] = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((target, port))
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    success = True
                    with stats_lock:
                        stats["attempted"] += 1
                        stats["succeeded"] += 1
                except OSError:
                    # Connection refused / timeout / DNS failure
                    remaining_attempts -= 1
                    with stats_lock:
                        stats["attempted"] += 1
                        if remaining_attempts > 0:
                            # This attempt failed but we'll retry
                            stats["retried"] += 1
                        else:
                            # No more retries, count as failed
                            stats["failed"] += 1
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                current_time = time.time()

    started: list[threading.Thread] = []
    for _ in range(threads):
        t = threading.Thread(target=flood, daemon=True)
        t.start()
        started.append(t)

    # Wait for all threads to complete
    for t in started:
        t.join()

    actual_duration = time.time() - start_time
    connections_per_second = (
        round(stats["attempted"] / actual_duration, 2) if actual_duration > 0 else 0
    )

    result: dict[str, Any] = {
        "target": target,
        "port": port,
        "threads": threads,
        "duration": duration,
        "timeout": timeout,
        "retries": retries,
        "actual_duration_seconds": round(actual_duration, 2),
        "connections_attempted": stats["attempted"],
        "connections_succeeded": stats["succeeded"],
        "connections_failed": stats["failed"],
        "connections_retried": stats["retried"],
        "connections_per_second": connections_per_second,
    }

    _output_stress_result(result, output_format)
    return result


def _output_stress_result(result: dict[str, Any], output_format: str) -> None:
    """Output stress test results in the specified format.

    Args:
        result: The stress test result dictionary.
        output_format: Output format ('text', 'json', or 'csv').
    """
    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))
    elif output_format == OUTPUT_FORMAT_CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(result.keys())
        writer.writerow(result.values())
        print(output.getvalue().strip())
    else:
        logger.info(
            "Stress test complete: %d attempts, %d succeeded, %d failed (%.2f conn/s)",
            result["connections_attempted"],
            result["connections_succeeded"],
            result["connections_failed"],
            result["connections_per_second"],
        )


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
        output_format: Output format ('text', 'json', or 'csv'). Default: 'text'.

    Returns:
        A dictionary containing exploit results with keys:
        - 'target': The target host
        - 'payload': The payload identifier
        - 'status': 'success' or 'error'
        - 'message': Status message
        - 'timestamp': ISO timestamp of execution

    Raises:
        ValueError: If *target* fails basic validation.
        Exception: Re-raised after logging for unexpected Scapy errors.

    Examples:
        >>> exploit_chain("127.0.0.1")  # doctest: +SKIP
    """
    target = _validate_target(target)
    output_format = _validate_output_format(output_format)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result: dict[str, Any] = {
        "target": target,
        "payload": payload,
        "status": "success",
        "message": "",
        "timestamp": timestamp,
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

    _output_exploit_result(result, output_format)
    return result


def _output_exploit_result(result: dict[str, Any], output_format: str) -> None:
    """Output exploit results in the specified format.

    Args:
        result: The exploit result dictionary.
        output_format: Output format ('text', 'json', or 'csv').
    """
    if output_format == OUTPUT_FORMAT_JSON:
        print(json.dumps(result, indent=2))
    elif output_format == OUTPUT_FORMAT_CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(result.keys())
        writer.writerow(result.values())
        print(output.getvalue().strip())


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


def main() -> int:
    """Parse CLI arguments and dispatch to the appropriate function.

    Sub-commands:
        scan    – vulnerability scan via nmap.
        stress  – connection-flood stress test.
        exploit – exploit-chain simulation.

    Global flags:
        --verbose, -v : Enable debug logging.
        --quiet, -q   : Suppress info messages, only show warnings/errors.
        --output-format, -f : Output format ('text', 'json', or 'csv').

    Returns:
        Exit code (0 for success, 1 for error, 2 for validation error).

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
        "--version", action="version", version=f"Terminal Pressure v{VERSION}"
    )
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
    stress_parser.add_argument(
        "--timeout",
        type=float,
        default=SOCKET_TIMEOUT,
        help=f"Socket timeout in seconds (default: {SOCKET_TIMEOUT}, range: {MIN_TIMEOUT}-{MAX_TIMEOUT})",
    )
    stress_parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Retries for failed connections (default: {DEFAULT_RETRIES}, max: {MAX_RETRIES})",
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

    try:
        if args.command == "scan":
            scan_vulns(args.target, output_format=args.output_format)
        elif args.command == "stress":
            stress_test(
                args.target,
                args.port,
                args.threads,
                args.duration,
                output_format=args.output_format,
                timeout=args.timeout,
                retries=args.retries,
            )
        elif args.command == "exploit":
            exploit_chain(args.target, args.payload, output_format=args.output_format)
        else:
            parser.print_help()
            return EXIT_SUCCESS
    except ValueError as exc:
        logger.error("Validation error: %s", exc)
        return EXIT_VALIDATION_ERROR
    except Exception as exc:
        logger.error("Error: %s", exc)
        return EXIT_ERROR

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
