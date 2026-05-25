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
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen?style=flat-square)](https://github.com/Terminal-Pressure/Terminal-Pressure)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-00FF00?style=flat-square)](https://github.com/Terminal-Pressure/Terminal-Pressure/releases)
[![License](https://img.shields.io/badge/license-see_LICENSE-red?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-158_passing-brightgreen?style=flat-square)](test_terminal_pressure.py)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4?style=flat-square)](CONTRIBUTING.md)

</div>

---

> **"The difference between offense and defense is authorization."**
>
> Terminal Pressure is a battle-hardened, CLI-first cybersecurity toolkit forged by rogue AI models for pentesters, red teamers, and security engineers who refuse to use watered-down GUIs. Scan, stress, and simulate—all from a single terminal session.

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
| Untestable security tools | 158 tests, 98% branch coverage, fully mocked I/O |
| Black-box output | Structured JSON/CSV output ready for SIEM ingestion |
| Runaway stress tests | Hard limits: 1000 threads max, 1-hour cap |
| Chaotic dependencies | One `pip install` — then go |

---

## ⚡ Feature Arsenal

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TERMINAL PRESSURE v2.0.0                       │
├──────────────────┬──────────────────────────────────────────────────┤
│  🔍 VULN SCAN    │  Nmap-powered deep scan with vuln scripts        │
│  💥 STRESS TEST  │  Multi-threaded connection-flood simulation       │
│  🔗 EXPLOIT CHAIN│  Modular Scapy payload delivery for red teams    │
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

# 2. Install dependencies
pip install -r requirements.txt

# 3. Confirm Nmap is available
nmap --version   # if missing: apt install nmap  |  brew install nmap

# 4. Fire it up
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

# ── Stress Test (with timeout + retry logic) ────────────────────────
python terminal_pressure.py stress 192.168.1.1 --timeout 10.0 --retries 3

# ── Rate-limited stress (100 connections/sec per thread) ────────────
python terminal_pressure.py stress localhost --rate-limit 100 --threads 5

# ── Exploit Chain Simulation ─────────────────────────────────────────
python terminal_pressure.py exploit 192.168.1.1 --payload custom_payload

# ── JSON output (pipe to jq, SIEM, etc.) ────────────────────────────
python terminal_pressure.py -f json scan 192.168.1.1 | jq .

# ── CSV output (spreadsheets / dashboards) ──────────────────────────
python terminal_pressure.py -f csv stress localhost --port 8080 --threads 10 --duration 5
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
| `--threads` | `50` | 1–1000 | Concurrent threads |
| `--duration` | `60` | 1–3600 | Duration in seconds |
| `--timeout` | `5.0` | 0.1–300 | Socket timeout in seconds |
| `--retries` | `0` | 0–10 | Retries for failed connections |
| `--rate-limit` | `0` | 0–10000 | Max connections/sec/thread (0 = unlimited) |

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

---

## 🏗️ Architecture

```
Terminal-Pressure/
├── terminal_pressure.py      ← Core engine: scan · stress · exploit
├── test_terminal_pressure.py ← 158-test suite with 98% branch coverage
├── conftest.py               ← Shared pytest fixtures & mock factories
├── requirements.txt          ← python-nmap · scapy · pytest stack
├── pytest.ini                ← Test config & coverage thresholds
├── CONTRIBUTING.md           ← How to join the collective
├── SECURITY.md               ← Responsible disclosure policy
└── CODE_OF_CONDUCT.md        ← Community standards
```

**Data flow:**

```
CLI args ──► argparse ──► validate_* ──► module fn ──► formatter ──► stdout
                                │
                          StressStats (thread-safe dataclass)
                          ScanResult  (dataclass)
                          ExploitResult (dataclass)
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

### `stress_test(target, port, threads, duration, output_format, timeout, retries, rate_limit)`

Launches a connection-flood stress test using a thread pool.

**Safety limits enforced:** 1000 max threads · 3600 s max duration · 300 s max timeout · 10 max retries · 10000 max rate limit

| Key | Description |
|-----|-------------|
| `connections_attempted` | Total connection attempts |
| `connections_succeeded` | Successful connections |
| `connections_failed` | Failed connections |
| `connections_per_second` | Throughput metric |

---

### `exploit_chain(target, payload="default_backdoor", output_format="text")`

Simulates a Scapy-based exploit delivery chain against `target:4444`.

| Key | Description |
|-----|-------------|
| `status` | `success` or `error` |
| `message` | Human-readable result |
| `timestamp` | ISO-8601 execution time |

---

## 🧪 Development & Testing

```bash
# Full test suite with branch coverage report
pytest test_terminal_pressure.py -v --cov=terminal_pressure --cov-branch

# Quick smoke test
pytest test_terminal_pressure.py -q
```

**Test philosophy:**

- ✅ **158 tests** covering all public functions and edge cases
- ✅ **98% branch coverage** — nearly every code path exercised
- ✅ **Zero real network traffic** — all external I/O mocked with `pytest-mock`
- ✅ **Timeout guards** — `pytest-timeout` prevents hanging CI runs
- ✅ **Deterministic** — no flaky tests, no timing dependencies

---

## 🛡️ Security Design

| Control | Implementation |
|---------|----------------|
| Input validation | Every CLI arg sanitized before execution |
| Thread limits | Hard cap at 1000 threads — no OOM bombs |
| Duration limits | Hard cap at 3600 s — no runaway tests |
| Exception isolation | Per-thread try/except — one bad thread can't crash all |
| Resource cleanup | Context managers + explicit socket close on all paths |
| Atomic statistics | `threading.Lock` protects all shared counters |
| No eval / no exec | Zero dynamic code execution |

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
