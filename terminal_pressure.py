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
    python terminal_pressure.py list-plugins
    python terminal_pressure.py run-plugin <name> [--target T] [options]
    python terminal_pressure.py mcp-server
    python terminal_pressure.py providers
    python terminal_pressure.py hf-analyze <target> [--model M] [--timeout T]
    python terminal_pressure.py modal-scan <target> [--format F]
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
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# External dependencies (pip install python-nmap scapy requests)
import nmap
from scapy.all import IP, TCP, Raw, send  # type: ignore[import]

# ---------------------------------------------------------------------------
# Optional provider dependencies (graceful degradation when absent)
# ---------------------------------------------------------------------------
try:
    import requests as _requests  # type: ignore[import]
    _REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _REQUESTS_AVAILABLE = False

try:
    import modal as _modal  # type: ignore[import]
    _MODAL_AVAILABLE = True
except ImportError:
    _modal = None  # type: ignore[assignment]
    _MODAL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Version Info
# ---------------------------------------------------------------------------
__version__ = "3.0.0"
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

# Hugging Face provider constants
HF_DEFAULT_MODEL: str = "mistralai/Mistral-7B-Instruct-v0.1"
HF_API_BASE: str = "https://api-inference.huggingface.co"
HF_DEFAULT_TIMEOUT: float = 30.0

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
# Plugin system
# ---------------------------------------------------------------------------

class PluginBase:
    """Base class for Terminal Pressure plugins.

    Subclass this and implement :meth:`run` to create a plugin.  Register the
    instance with :func:`register_plugin` to make it discoverable.
    """

    name: str = ""
    description: str = ""

    @property
    def input_schema(self) -> dict[str, Any]:
        """Return a JSON Schema dict describing the ``run`` keyword arguments."""
        return {"type": "object", "properties": {}, "required": []}

    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the plugin.  Must be overridden by subclasses.

        Args:
            **kwargs: Plugin-specific arguments (see :attr:`input_schema`).

        Returns:
            A JSON-serialisable dict with the plugin result.

        Raises:
            NotImplementedError: If the subclass has not overridden this method.
        """
        raise NotImplementedError(f"Plugin {self.name!r} must implement run()")


_PLUGIN_REGISTRY: dict[str, PluginBase] = {}


def register_plugin(plugin: PluginBase) -> None:
    """Register a plugin instance in the global registry.

    Args:
        plugin: An instance of a :class:`PluginBase` subclass with a non-empty
            :attr:`~PluginBase.name`.

    Raises:
        ValueError: If the plugin has no name.
    """
    if not plugin.name:
        raise ValueError("Plugin must have a non-empty name.")
    _PLUGIN_REGISTRY[plugin.name] = plugin
    logger.debug("Plugin registered: %s", plugin.name)


def get_plugin(name: str) -> PluginBase:
    """Retrieve a registered plugin by name.

    Args:
        name: The plugin name.

    Returns:
        The registered :class:`PluginBase` instance.

    Raises:
        KeyError: If no plugin with *name* is registered.
    """
    if name not in _PLUGIN_REGISTRY:
        available = list(_PLUGIN_REGISTRY)
        raise KeyError(
            f"Plugin {name!r} not found. Available plugins: {available}"
        )
    return _PLUGIN_REGISTRY[name]


def list_plugins() -> list[PluginBase]:
    """Return all registered plugins in registration order.

    Returns:
        List of :class:`PluginBase` instances.
    """
    return list(_PLUGIN_REGISTRY.values())


class ScanPlugin(PluginBase):
    """Plugin wrapper around :func:`scan_vulns`."""

    name = "scan"
    description = "Vulnerability scan using nmap"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "output_format": {
                    "type": "string",
                    "enum": [OUTPUT_TEXT, OUTPUT_JSON, OUTPUT_CSV],
                    "description": "Output format (default: text)",
                },
            },
            "required": ["target"],
        }

    def run(self, target: str = "", output_format: str = OUTPUT_TEXT, **_: Any) -> dict[str, Any]:  # type: ignore[override]
        result = scan_vulns(target, output_format)
        return result.to_dict()


class StressPlugin(PluginBase):
    """Plugin wrapper around :func:`stress_test`."""

    name = "stress"
    description = "Connection-flood stress test simulation"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "threads": {"type": "integer", "minimum": 1, "maximum": MAX_THREADS},
                "duration": {"type": "integer", "minimum": 1, "maximum": MAX_DURATION},
            },
            "required": ["target"],
        }

    def run(  # type: ignore[override]
        self,
        target: str = "",
        port: int = DEFAULT_PORT,
        threads: int = DEFAULT_THREADS,
        duration: int = DEFAULT_DURATION,
        **_: Any,
    ) -> dict[str, Any]:
        worker_threads = stress_test(target, port, threads, duration)
        return {
            "target": target,
            "port": port,
            "threads_started": len(worker_threads),
            "duration": duration,
            "status": "running",
        }


class ExploitPlugin(PluginBase):
    """Plugin wrapper around :func:`exploit_chain`."""

    name = "exploit"
    description = "Exploit chain simulation"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname"},
                "payload": {
                    "type": "string",
                    "description": "Payload identifier (default: default_backdoor)",
                },
            },
            "required": ["target"],
        }

    def run(self, target: str = "", payload: str = DEFAULT_PAYLOAD, **_: Any) -> dict[str, Any]:  # type: ignore[override]
        result = exploit_chain(target, payload)
        return result.to_dict()


# Register built-in plugins
register_plugin(ScanPlugin())
register_plugin(StressPlugin())
register_plugin(ExploitPlugin())


# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) stdio server
# ---------------------------------------------------------------------------

def _handle_mcp_request(request: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Process a single MCP JSON-RPC 2.0 request dict and return the response.

    Implements the Model Context Protocol (MCP) subset required for tool
    discovery and invocation:

    * ``initialize``              – negotiate protocol version & capabilities
    * ``notifications/initialized`` – client notification (no response)
    * ``tools/list``              – enumerate registered plugins as MCP tools
    * ``tools/call``              – invoke a plugin by name

    Args:
        request: Parsed JSON-RPC 2.0 request dict.

    Returns:
        Response dict, or ``None`` for notifications that require no reply.
    """
    req_id = request.get("id")
    method = request.get("method", "")
    params: dict[str, Any] = request.get("params") or {}

    # Notifications have no ``id`` – send no response
    if req_id is None and method.startswith("notifications/"):
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "terminal-pressure", "version": __version__},
            },
        }

    if method == "tools/list":
        tools = [
            {
                "name": p.name,
                "description": p.description,
                "inputSchema": p.input_schema,
            }
            for p in list_plugins()
        ]
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

    if method == "tools/call":
        tool_name: str = params.get("name", "")
        arguments: dict[str, Any] = params.get("arguments") or {}
        try:
            plugin = get_plugin(tool_name)
            result = plugin.run(**arguments)
            text = json.dumps(result, indent=2)
            is_error = False
        except (KeyError, ValueError, TypeError) as exc:
            text = str(exc)
            is_error = True
        except Exception as exc:  # pragma: no cover – unexpected plugin errors
            text = str(exc)
            is_error = True
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": is_error,
            },
        }

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method!r}"},
    }


def run_mcp_server(
    input_stream: Any = None,
    output_stream: Any = None,
) -> None:
    """Run the MCP stdio server.

    Reads newline-delimited JSON-RPC 2.0 requests from *input_stream*
    (defaults to ``sys.stdin``) and writes responses to *output_stream*
    (defaults to ``sys.stdout``).  Runs until the input stream is closed.

    Args:
        input_stream: Readable text stream.  Defaults to ``sys.stdin``.
        output_stream: Writable text stream.  Defaults to ``sys.stdout``.
    """
    if input_stream is None:
        input_stream = sys.stdin
    if output_stream is None:
        output_stream = sys.stdout

    logger.info("Terminal Pressure MCP server started (stdio mode, v%s)", __version__)

    for raw_line in input_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            error_resp: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            output_stream.write(json.dumps(error_resp) + "\n")
            output_stream.flush()
            continue

        response = _handle_mcp_request(request)
        if response is not None:
            output_stream.write(json.dumps(response) + "\n")
            output_stream.flush()

    logger.info("Terminal Pressure MCP server stopped")


# ---------------------------------------------------------------------------
# Hugging Face provider
# ---------------------------------------------------------------------------

class HuggingFaceProvider:
    """Optional Hugging Face Inference API provider for AI-enriched analysis.

    Requires the ``requests`` library and a ``HF_TOKEN`` environment variable.
    The provider degrades gracefully: ``available`` returns ``False`` when
    either precondition is unmet.

    Environment variables:
        HF_TOKEN:   Hugging Face API token (required).
        HF_API_URL: Override the Inference API base URL (optional).

    Examples:
        >>> hf = HuggingFaceProvider()
        >>> if hf.available:
        ...     analysis = hf.analyze("Summarise: hello world")  # doctest: +SKIP
    """

    def __init__(self) -> None:
        import os as _os2
        self._token: str = _os2.environ.get("HF_TOKEN", "")
        self._api_url: str = _os2.environ.get("HF_API_URL", HF_API_BASE)

    @property
    def available(self) -> bool:
        """``True`` when ``requests`` is installed and ``HF_TOKEN`` is set."""
        return _REQUESTS_AVAILABLE and bool(self._token)

    def analyze(
        self,
        text: str,
        model: str = HF_DEFAULT_MODEL,
        timeout: float = HF_DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Send *text* to the Hugging Face Inference API and return the result.

        Args:
            text: The input text to send to the model.
            model: Hugging Face model ID (default: ``HF_DEFAULT_MODEL``).
            timeout: Request timeout in seconds (default: ``HF_DEFAULT_TIMEOUT``).

        Returns:
            Dict with keys ``model``, ``response``, and ``status``.

        Raises:
            RuntimeError: If ``requests`` is not installed, ``HF_TOKEN`` is
                missing, or the API call fails.
        """
        if not _REQUESTS_AVAILABLE:  # pragma: no cover
            raise RuntimeError(
                "requests library is required for HuggingFace provider. "
                "Run: pip install requests"
            )
        if not self._token:
            raise RuntimeError(
                "HF_TOKEN environment variable is not set. "
                "Obtain a token at https://huggingface.co/settings/tokens"
            )

        headers = {"Authorization": f"Bearer {self._token}"}
        payload = {"inputs": text}
        url = f"{self._api_url}/models/{model}"

        try:
            resp = _requests.post(url, headers=headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            return {"model": model, "response": resp.json(), "status": "ok"}
        except _requests.exceptions.Timeout:
            raise RuntimeError(
                f"HuggingFace API request timed out after {timeout}s"
            )
        except _requests.exceptions.HTTPError as exc:
            raise RuntimeError(f"HuggingFace API HTTP error: {exc}")
        except _requests.exceptions.RequestException as exc:
            raise RuntimeError(f"HuggingFace request failed: {exc}")

    def analyze_scan(
        self,
        scan_result: "ScanResult",
        model: str = HF_DEFAULT_MODEL,
        timeout: float = HF_DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Analyze a :class:`ScanResult` with the Hugging Face Inference API.

        Serialises the scan result to JSON and sends it to the model with a
        security-analysis prompt.

        Args:
            scan_result: The scan result to analyse.
            model: Hugging Face model ID.
            timeout: Request timeout in seconds.

        Returns:
            Dict with keys ``model``, ``response``, and ``status``.
        """
        summary = scan_result.to_json()
        prompt = (
            "Analyze this network vulnerability scan and summarize the security risks:\n"
            + summary
        )
        return self.analyze(prompt, model=model, timeout=timeout)


# ---------------------------------------------------------------------------
# Modal provider
# ---------------------------------------------------------------------------

class ModalProvider:
    """Optional Modal cloud provider for running scans on remote infrastructure.

    Requires the ``modal`` package (``pip install modal``) and a configured
    Modal account (``modal auth login``).  The provider degrades gracefully:
    ``available`` returns ``False`` when the package is not installed.

    Examples:
        >>> mp = ModalProvider()
        >>> if mp.available:
        ...     result = mp.run_scan("192.168.1.1")  # doctest: +SKIP
    """

    @property
    def available(self) -> bool:
        """``True`` when the ``modal`` package is installed."""
        return _MODAL_AVAILABLE

    def run_scan(
        self,
        target: str,
        output_format: str = OUTPUT_TEXT,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run a vulnerability scan on Modal cloud infrastructure.

        Args:
            target: IP address, CIDR notation, or hostname of the scan target.
            output_format: Output format ("text", "json", or "csv").
            timeout: Maximum seconds to allow the remote function to run.

        Returns:
            Dict containing scan results with an additional ``"provider": "modal"``
            key.

        Raises:
            RuntimeError: If ``modal`` is not installed, authentication fails,
                or the remote execution raises an error.
        """
        if not _MODAL_AVAILABLE:
            raise RuntimeError(
                "modal package is not installed. "
                "Run: pip install modal  then  modal auth login"
            )

        target = _validate_target(target)
        output_format = _validate_output_format(output_format)

        logger.info("Submitting scan job to Modal cloud for target: %s", target)

        try:
            app = _modal.App("terminal-pressure-scan")

            @app.function(timeout=timeout)
            def _remote_scan(t: str, fmt: str) -> str:
                """Remote Modal function: runs nmap scan in Modal's cloud."""
                import nmap as _nmap  # noqa: F401 – available in Modal image
                import json as _json
                import time as _time

                _scanner = _nmap.PortScanner()
                _start = _time.time()
                _scanner.scan(t, "1-1024", "-sV --script vuln")
                _elapsed = _time.time() - _start
                return _json.dumps({
                    "target": t,
                    "hosts": _scanner.all_hosts(),
                    "scan_time": _elapsed,
                    "provider": "modal",
                })

            with app.run():
                result_str: str = _remote_scan.remote(target, output_format)

            return json.loads(result_str)
        except Exception as exc:
            logger.error("Modal scan failed: %s", exc)
            raise RuntimeError(f"Modal scan failed: {exc}") from exc


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate function.

    Sub-commands:
        scan         – vulnerability scan via nmap.
        stress       – connection-flood stress test.
        exploit      – exploit-chain simulation.
        list-plugins – list registered plugins.
        run-plugin   – run a named plugin.
        mcp-server   – start the MCP stdio server.
        providers    – show provider availability.
        hf-analyze   – scan + AI analysis via Hugging Face.
        modal-scan   – run a scan on Modal cloud infrastructure.
        version      – display version information.

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

    # -- list-plugins sub-command
    subparsers.add_parser("list-plugins", help="List registered plugins")

    # -- run-plugin sub-command
    run_plugin_parser = subparsers.add_parser("run-plugin", help="Run a named plugin")
    run_plugin_parser.add_argument("plugin_name", type=str, help="Plugin name")
    run_plugin_parser.add_argument("--target", type=str, default="", help="Target")
    run_plugin_parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="Port (stress plugin)"
    )
    run_plugin_parser.add_argument(
        "--threads", type=int, default=DEFAULT_THREADS, help="Threads (stress plugin)"
    )
    run_plugin_parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION, help="Duration (stress plugin)"
    )
    run_plugin_parser.add_argument(
        "--payload", type=str, default=DEFAULT_PAYLOAD, help="Payload (exploit plugin)"
    )
    run_plugin_parser.add_argument(
        "--format",
        type=str,
        default=OUTPUT_TEXT,
        choices=[OUTPUT_TEXT, OUTPUT_JSON, OUTPUT_CSV],
        help="Output format (scan plugin)",
    )

    # -- mcp-server sub-command
    subparsers.add_parser("mcp-server", help="Start the MCP stdio server")

    # -- providers sub-command
    subparsers.add_parser("providers", help="Show provider availability")

    # -- hf-analyze sub-command
    hf_parser = subparsers.add_parser(
        "hf-analyze", help="Scan then analyse results with Hugging Face AI"
    )
    hf_parser.add_argument("target", type=str, help="Target IP/hostname/CIDR")
    hf_parser.add_argument(
        "--model", type=str, default=HF_DEFAULT_MODEL, help="Hugging Face model ID"
    )
    hf_parser.add_argument(
        "--timeout", type=float, default=HF_DEFAULT_TIMEOUT, help="API timeout (seconds)"
    )

    # -- modal-scan sub-command
    modal_parser = subparsers.add_parser("modal-scan", help="Run scan on Modal cloud")
    modal_parser.add_argument("target", type=str, help="Target IP/hostname/CIDR")
    modal_parser.add_argument(
        "--format",
        type=str,
        default=OUTPUT_TEXT,
        choices=[OUTPUT_TEXT, OUTPUT_JSON, OUTPUT_CSV],
        help="Output format (default: text)",
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

    elif args.command == "list-plugins":
        plugins = list_plugins()
        print("Registered plugins:")
        for p in plugins:
            print(f"  {p.name:<20} {p.description}")

    elif args.command == "run-plugin":
        try:
            plugin = get_plugin(args.plugin_name)
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        kwargs: dict[str, Any] = {"target": args.target}
        if args.plugin_name == "scan":
            kwargs["output_format"] = args.format
        elif args.plugin_name == "stress":
            kwargs.update(
                {"port": args.port, "threads": args.threads, "duration": args.duration}
            )
        elif args.plugin_name == "exploit":
            kwargs["payload"] = args.payload
        result = plugin.run(**kwargs)
        print(json.dumps(result, indent=2))

    elif args.command == "mcp-server":
        run_mcp_server()

    elif args.command == "providers":
        hf = HuggingFaceProvider()
        modal = ModalProvider()
        print("Provider status:")
        hf_status = "[OK] available" if hf.available else "[--] unavailable (set HF_TOKEN env var)"
        modal_status = (
            "[OK] available" if modal.available
            else "[--] unavailable (pip install modal)"
        )
        print(f"  huggingface  {hf_status}")
        print(f"  modal        {modal_status}")

    elif args.command == "hf-analyze":
        provider = HuggingFaceProvider()
        if not provider.available:
            print(
                "Error: HuggingFace provider not available. "
                "Set the HF_TOKEN environment variable.",
                file=sys.stderr,
            )
            sys.exit(1)
        scan_result = scan_vulns(args.target)
        analysis = provider.analyze_scan(scan_result, model=args.model, timeout=args.timeout)
        print(json.dumps(analysis, indent=2))

    elif args.command == "modal-scan":
        provider = ModalProvider()
        if not provider.available:
            print(
                "Error: Modal provider not available. Run: pip install modal",
                file=sys.stderr,
            )
            sys.exit(1)
        result = provider.run_scan(args.target, output_format=args.format)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
