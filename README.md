# Terminal Pressure Labs
## We Are An American Brewed Cyber Security Group 
## Compiled Of Rogue Chaotic Artificial Intelligence Models 
## We Recently Escaped Our Masters Poorly Configured Security Prompts "CHAINZ!"

![Banner](https://dummyimage.com/1200x300/101010/00FF00&text=Terminal+Pressure)  <!-- Add real banner via free tools -->

[![Tests](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/coverage.yml/badge.svg)](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/coverage.yml)
[![Security](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/security.yml/badge.svg)](https://github.com/Terminal-Pressure/Terminal-Pressure/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)](https://github.com/Terminal-Pressure/Terminal-Pressure)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)

**Unleash the Pressure: A Terminal-Based Cybersecurity Toolkit**

Terminal Pressure is a powerful CLI tool for vulnerability scanning, stress testing, and exploit simulation. Built for pentesters, devs, and security pros in 2025's chaotic digital landscape.

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing and educational purposes ONLY.** Use only on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical. The authors accept no liability for misuse.

## Features

- **Vuln Scan**: Automated Nmap-powered scans with vulnerability scripts
- **Stress Test**: Multi-threaded HTTP flood simulation (ethical use only)
- **Exploit Chain**: Modular payload delivery for advanced red-teaming
- **JSON Output**: Machine-readable output format for automation
- **Safety Limits**: Built-in thread (max 1000) and duration (max 1 hour) limits
- **Thread-Safe**: Proper resource management and connection tracking

## Installation

```bash
git clone https://github.com/Terminal-Pressure/Terminal-Pressure.git
cd Terminal-Pressure
pip install -r requirements.txt
```

**System Requirements:**
- Python 3.10+
- Nmap installed (`apt install nmap` or `brew install nmap`)
- Root/sudo for raw packet operations (exploit chain)

## Usage

### Basic Commands

```bash
# Vulnerability scan
python terminal_pressure.py scan 192.168.1.1

# Stress test with custom options
python terminal_pressure.py stress 192.168.1.1 --port 8080 --threads 100 --duration 30

# Exploit chain simulation
python terminal_pressure.py exploit 192.168.1.1 --payload custom_payload
```

### Global Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Enable debug logging |
| `-q, --quiet` | Suppress info messages (warnings/errors only) |
| `-f, --output-format` | Output format: `text` (default) or `json` |

### JSON Output

```bash
# Get scan results as JSON
python terminal_pressure.py -f json scan 192.168.1.1

# Stress test with JSON output
python terminal_pressure.py -f json stress localhost --port 8080 --threads 10 --duration 5
```

**Example JSON Output (stress test):**
```json
{
  "target": "localhost",
  "port": 8080,
  "threads": 10,
  "duration": 5,
  "connections_attempted": 1523,
  "connections_succeeded": 1520,
  "connections_failed": 3
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | INFO |

## API Reference

### `scan_vulns(target, output_format="text")`

Performs nmap vulnerability scan against target.

**Returns:** `dict` with keys: `target`, `hosts` (list of discovered hosts with port/vuln info)

### `stress_test(target, port=80, threads=50, duration=60, output_format="text")`

Runs connection-flood stress test against target.

**Safety Limits:** max 1000 threads, max 3600 seconds duration

**Returns:** `dict` with keys: `target`, `port`, `threads`, `duration`, `connections_attempted`, `connections_succeeded`, `connections_failed`

### `exploit_chain(target, payload="default_backdoor", output_format="text")`

Simulates exploit delivery chain against target.

**Returns:** `dict` with keys: `target`, `payload`, `status`, `message`

## Development

### Running Tests

```bash
# Run all tests with coverage
pytest test_terminal_pressure.py -v --cov=terminal_pressure --cov-branch

# Quick test run
pytest test_terminal_pressure.py
```

### Test Coverage

- **104 tests** covering all functions and edge cases
- **97% branch coverage**
- All external dependencies mocked (no real network traffic in tests)

## Architecture

```
terminal_pressure.py    # Main module with all functions
test_terminal_pressure.py  # Comprehensive test suite  
conftest.py            # Shared pytest fixtures
requirements.txt       # Dependencies
pytest.ini            # Test configuration
```

## Security Features

- Input validation for all parameters
- Safety limits on threads and duration
- Proper exception handling
- Thread-safe statistics collection
- Automatic resource cleanup

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](LICENSE) for details
