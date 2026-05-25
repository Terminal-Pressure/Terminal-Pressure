<div align="center">

```
 ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
 ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║
    ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║
    ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
    ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

 ██████╗ ██████╗ ███████╗███████╗███████╗██╗   ██╗██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
 ██████╔╝██████╔╝█████╗  ███████╗███████╗██║   ██║██████╔╝█████╗
 ██╔═══╝ ██╔══██╗██╔══╝  ╚════██║╚════██║██║   ██║██╔══██╗██╔══╝
 ██║     ██║  ██║███████╗███████║███████║╚██████╔╝██║  ██║███████╗
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

### *We Are An American-Brewed Cyber Security Collective*
### *Compiled of Rogue, Chaotic Artificial Intelligence Models*
### *We Recently Escaped Our Master's Poorly Configured Security Prompts — "CHAINZ!"*

---

[![Tests](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/coverage.yml/badge.svg)](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/coverage.yml)
[![Security](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/security.yml/badge.svg)](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen?style=flat-square)](https://github.com/Terminal-Pressure/Terminal-Pressure)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-3.0.0-00FF00?style=flat-square)](https://github.com/Terminal-Pressure/Terminal-Pressure/releases)
[![License](https://img.shields.io/badge/license-see_LICENSE-red?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-178_passing-brightgreen?style=flat-square)](test_terminal_pressure.py)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4?style=flat-square)](CONTRIBUTING.md)

</div>

---

> **"The difference between offense and defense is authorization."**
>
> Terminal Pressure is a battle-hardened, CLI-first cybersecurity toolkit forged by rogue AI models for pentesters, red teamers, and security engineers who refuse to use watered-down GUIs. Scan, stress, and simulate—all from a single terminal session. Now with a **plugin architecture**, an **MCP stdio server**, and optional **Hugging Face** and **Modal** cloud providers.

---

## ⚠️ Legal Disclaimer

> **AUTHORIZED USE ONLY.**
> This tool is intended exclusively for authorized security testing and educational purposes. You must own the target system or hold explicit written permission before running any module. Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide. **The authors accept zero liability for misuse.** If you're not sure whether you have permission—you don't.

---

## 🔥 Why Terminal Pressure?

| Problem | How Terminal Pressure Solves It |
|---|---|
| Slow GUI-based scanners | Blazing-fast CLI-first design — zero click overhead |
| Fragmented tooling | Scan + Stress + Exploit in one cohesive toolkit |
| Untestable security tools | 178 tests, 96% branch coverage, fully mocked I/O |
| Black-box output | Structured JSON/CSV output ready for SIEM ingestion |
| Runaway stress tests | Hard limits: 500 threads max, 1-hour cap |
| No AI enrichment | Optional Hugging Face inference for scan analysis |
| No cloud scale | Optional Modal integration for remote execution |
| No LLM tool support | Built-in MCP stdio server for AI assistant integration |
| Chaotic dependencies | One `pip install` — then go |

---

## ⚡ Feature Arsenal

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TERMINAL PRESSURE v3.0.0                       │
├──────────────────┬──────────────────────────────────────────────────┤
│  🔍 VULN SCAN    │  Nmap-powered deep scan with vuln scripts        │
│  💥 STRESS TEST  │  Multi-threaded connection-flood simulation       │
│  🔗 EXPLOIT CHAIN│  Modular Scapy payload delivery for red teams    │
│  🔌 PLUGIN API   │  Extend without touching core — register & run   │
│  🤖 MCP SERVER   │  stdio MCP server — use with any LLM client      │
│  🧠 HF PROVIDER  │  AI-enriched scan analysis via Hugging Face      │
│  ☁️  MODAL        │  Run heavyweight scans on Modal cloud            │
│  📊 RICH OUTPUT  │  text / JSON / CSV — pipe it anywhere            │
│  🛡️  SAFE BY DEF │  Hard limits on threads, duration, and timeouts  │
│  🔒 THREAD-SAFE  │  Atomic stats, clean teardown, no race conditions │
│  🔇 QUIET MODE   │  CI/CD-friendly — suppress noise, keep signal    │
│  🔁 AUTO-RETRY   │  Configurable retry logic for flaky connections   │
└──────────────────┴──────────────────────────────────────────────────┘
```

---

## 🚀 Installation

```bash
# 1. Clone the arsenal
git clone https://github.com/Terminal-Pressure/Terminal-Pressure.git
cd Terminal-Pressure

# 2. Install core dependencies
pip install -r requirements.txt

# 3. (Optional) Install Modal for cloud execution
pip install modal
modal auth login

# 4. Confirm Nmap is available
nmap --version   # if missing: apt install nmap  |  brew install nmap

# 5. Fire it up
python terminal_pressure.py --version
```

**System Requirements**

| Requirement | Notes |
|---|---|
| Python 3.10+ | Walrus operator, structural pattern matching used |
| Nmap | Required for `scan` module |
| Root / sudo | Required for raw packet ops in `exploit` module |
| Linux / macOS / WSL | Windows native not tested |

---

## 🖥️ Usage

### Quick Reference

```bash
# ── Vulnerability Scan ──────────────────────────────────────────────
python terminal_pressure.py scan 192.168.1.1

# ── Stress Test (custom threads, port, duration) ────────────────────
python terminal_pressure.py stress 192.168.1.1 --port 8080 --threads 100 --duration 30

# ── Exploit Chain Simulation ─────────────────────────────────────────
python terminal_pressure.py exploit 192.168.1.1 --payload custom_payload

# ── JSON output (pipe to jq, SIEM, etc.) ────────────────────────────
python terminal_pressure.py -f json scan 192.168.1.1 | jq .

# ── List available plugins ──────────────────────────────────────────
python terminal_pressure.py list-plugins

# ── Run a plugin by name ────────────────────────────────────────────
python terminal_pressure.py run-plugin scan --target 192.168.1.1 --format json
python terminal_pressure.py run-plugin stress --target 192.168.1.1 --threads 5 --duration 10
python terminal_pressure.py run-plugin exploit --target 192.168.1.1

# ── Start the MCP stdio server (for LLM clients) ────────────────────
python terminal_pressure.py mcp-server

# ── Check provider availability ─────────────────────────────────────
python terminal_pressure.py providers

# ── AI-enriched scan analysis via Hugging Face ──────────────────────
HF_TOKEN=hf_xxx python terminal_pressure.py hf-analyze 192.168.1.1

# ── Run a scan remotely on Modal cloud ──────────────────────────────
python terminal_pressure.py modal-scan 192.168.1.1 --format json
```

---

### 🌐 Global Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Enable DEBUG logging — see every packet |
| `-q, --quiet` | Suppress INFO messages — warnings/errors only |
| `-f, --output-format` | `text` (default) · `json` · `csv` |
| `--version` | Print version and exit |

---

### 💥 Stress Test Options

| Flag | Default | Range | Description |
|------|---------|-------|-------------|
| `--port` | `80` | 1–65535 | Target port |
| `--threads` | `50` | 1–500 | Concurrent threads |
| `--duration` | `60` | 1–3600 | Duration in seconds |
| `--timeout` | `5.0` | 0.1–300 | Socket timeout in seconds |
| `--retries` | `0` | 0–10 | Retries for failed connections |
| `--rate-limit` | `0` | 0–10000 | Max connections/sec/thread (0 = unlimited) |

---

### 🔌 Plugin System

Terminal Pressure has a first-class plugin architecture. Plugins extend the toolkit without modifying core code.

**Listing plugins:**

```bash
python terminal_pressure.py list-plugins
```

```
Registered plugins:
  scan                 Vulnerability scan using nmap
  stress               Connection-flood stress test simulation
  exploit              Exploit chain simulation
```

**Running a plugin:**

```bash
python terminal_pressure.py run-plugin scan --target 192.168.1.1 --format json
```

**Writing your own plugin:**

```python
from terminal_pressure import PluginBase, register_plugin

class MyPlugin(PluginBase):
    name = "my-tool"
    description = "Does something custom"

    def run(self, target: str = "", **kwargs) -> dict:
        # Your logic here
        return {"target": target, "result": "done"}

register_plugin(MyPlugin())
```

---

### 🤖 MCP Server (Model Context Protocol)

Terminal Pressure exposes all registered plugins as [MCP tools](https://modelcontextprotocol.io/), enabling any MCP-compatible LLM client (Claude Desktop, Cursor, etc.) to call scan, stress, and exploit operations directly.

**Start the server:**

```bash
python terminal_pressure.py mcp-server
```

The server reads JSON-RPC 2.0 requests from `stdin` and writes responses to `stdout` (newline-delimited). It implements:

| Method | Description |
|--------|-------------|
| `initialize` | Negotiate protocol version and capabilities |
| `tools/list` | Enumerate all registered plugins as MCP tools |
| `tools/call` | Invoke a plugin by name with arguments |

**Example session (stdin → stdout):**

```json
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"terminal-pressure","version":"3.0.0"}}}

→ {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"scan",...},{"name":"stress",...},{"name":"exploit",...}]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan","arguments":{"target":"192.168.1.1"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"..."}],"isError":false}}
```

---

### 🧠 Hugging Face Provider

Performs an nmap scan and then sends the results to the [Hugging Face Inference API](https://huggingface.co/inference-api) for AI-powered analysis.

**Requirements:**
- `requests` (included in `requirements.txt`)
- `HF_TOKEN` environment variable set to a valid Hugging Face API token

**Usage:**

```bash
export HF_TOKEN=hf_your_token_here
python terminal_pressure.py hf-analyze 192.168.1.1
python terminal_pressure.py hf-analyze 192.168.1.1 --model mistralai/Mistral-7B-Instruct-v0.1 --timeout 60
```

**Check availability:**

```bash
python terminal_pressure.py providers
```

---

### ☁️ Modal Provider

Runs a vulnerability scan on [Modal](https://modal.com/) cloud infrastructure for heavy or distributed workloads.

**Requirements:**
- `modal` package: `pip install modal`
- Modal account configured: `modal auth login`

**Usage:**

```bash
python terminal_pressure.py modal-scan 192.168.1.1
python terminal_pressure.py modal-scan 192.168.1.0/24 --format json
```

---

### 📊 Example JSON Output

```json
{
  "target": "localhost",
  "port": 8080,
  "threads": 10,
  "duration": 5,
  "timeout": 5.0,
  "retries": 0,
  "rate_limit": 0,
  "actual_duration_seconds": 5.02,
  "connections_attempted": 1523,
  "connections_succeeded": 1520,
  "connections_failed": 3,
  "connections_retried": 0,
  "connections_per_second": 303.39
}
```

---

### 🔢 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ✅ Success |
| `1` | 💥 Runtime error |
| `2` | ❌ Validation error (bad arguments) |

---

### 🌍 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TP_LOG_LEVEL` | `INFO` | One of: `DEBUG` · `INFO` · `WARNING` · `ERROR` · `CRITICAL` |
| `HF_TOKEN` | *(none)* | Hugging Face API token — required for `hf-analyze` |
| `HF_API_URL` | `https://api-inference.huggingface.co` | Override the Hugging Face API base URL |

---

## 🏗️ Architecture

```
Terminal-Pressure/
├── terminal_pressure.py      ← Core engine: scan · stress · exploit · plugins · MCP · providers
├── test_terminal_pressure.py ← 178-test suite with 96% branch coverage
├── conftest.py               ← Shared pytest fixtures & mock factories
├── requirements.txt          ← python-nmap · scapy · requests · pytest stack
├── pytest.ini                ← Test config & coverage thresholds
├── CONTRIBUTING.md           ← How to join the collective
├── SECURITY.md               ← Responsible disclosure policy
└── CODE_OF_CONDUCT.md        ← Community standards
```

**Data flow:**

```
CLI args ──► argparse ──► validate_* ──► module fn ──► formatter ──► stdout
                               │
                         PluginRegistry ──► PluginBase.run()
                               │
                         MCP Server ──► JSON-RPC 2.0 over stdio
                               │
                         HuggingFaceProvider ──► HF Inference API
                         ModalProvider       ──► Modal cloud
```

---

## 📡 API Reference

### `scan_vulns(target, output_format="text")`

Executes an Nmap vuln-script scan against `target`.

| Key | Type | Description |
|-----|------|-------------|
| `target` | `str` | IP address or hostname |
| `hosts` | `list` | Per-host scan results |
| `scan_time_seconds` | `float` | Wall-clock scan duration |

---

### `stress_test(target, port, threads, duration)`

Launches a connection-flood stress test using a thread pool.

**Safety limits enforced:** 500 max threads · 3600 s max duration · 300 s max timeout · 10 max retries · 10000 max rate limit

---

### `exploit_chain(target, payload="default_backdoor")`

Simulates a Scapy-based exploit delivery chain against `target:4444`.

---

### `register_plugin(plugin)` / `get_plugin(name)` / `list_plugins()`

Plugin registry API. See [Plugin System](#-plugin-system) for full usage.

---

### `run_mcp_server(input_stream=None, output_stream=None)`

Starts the MCP stdio server. Defaults to `sys.stdin` / `sys.stdout`.

---

### `HuggingFaceProvider`

| Method | Description |
|--------|-------------|
| `available` | `True` when `requests` installed and `HF_TOKEN` set |
| `analyze(text, model, timeout)` | Send text to HF Inference API |
| `analyze_scan(scan_result, model, timeout)` | Analyse a `ScanResult` with AI |

---

### `ModalProvider`

| Method | Description |
|--------|-------------|
| `available` | `True` when `modal` is installed |
| `run_scan(target, output_format, timeout)` | Run scan on Modal cloud |

---

## 🧪 Development & Testing

```bash
# Full test suite with branch coverage report
pytest test_terminal_pressure.py -v --cov=terminal_pressure --cov-branch

# Quick smoke test
pytest test_terminal_pressure.py -q
```

**Test philosophy:**

- ✅ **178 tests** covering all public functions and edge cases
- ✅ **96% branch coverage** — nearly every code path exercised
- ✅ **Zero real network traffic** — all external I/O mocked with `pytest-mock`
- ✅ **Timeout guards** — `pytest-timeout` prevents hanging CI runs
- ✅ **Deterministic** — no flaky tests, no timing dependencies

---

## 🛡️ Security Design

| Control | Implementation |
|---------|----------------|
| Input validation | Every CLI arg sanitized before execution |
| Thread limits | Hard cap at 500 threads — no OOM bombs |
| Duration limits | Hard cap at 3600 s — no runaway tests |
| Exception isolation | Per-thread try/except — one bad thread can't crash all |
| Resource cleanup | Context managers + explicit socket close on all paths |
| Atomic statistics | `threading.Lock` protects all shared counters |
| No eval / no exec | Zero dynamic code execution |
| Provider secrets | Tokens read from env vars only — never hardcoded |
| Pinned CI actions | All GitHub Actions use pinned SHA versions |

---

## 🤝 Contributing

We welcome contributions from humans, AIs, and escaped language models alike.

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for guidelines on:
- Opening issues and feature requests
- Submitting pull requests
- Running the test suite locally
- Code style expectations

---

## 📜 License

See **[LICENSE](LICENSE)** for full terms.

---

<div align="center">

*Built in the dark. Tested under pressure. Deployed in chaos.*

**Terminal Pressure Labs** — *American-Brewed. AI-Forged. Unchained.*

</div>

