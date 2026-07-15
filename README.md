# Lightweight IDS

[English](README.md) | [简体中文](README.zh-CN.md)

Lightweight IDS is a local intrusion detection and analyst-workflow project built with Python 3.11, Scapy, SQLite, PySide6, and a React-based modern frontend. It supports offline packet analysis, live capture, rule-based detection, endpoint telemetry, alert investigation, asset-aware risk scoring, and defensive report export.

The project is designed for coursework, authorized laboratories, and defensive analysis on systems and traffic you are permitted to inspect.

## Application Options

| Interface | Start command | Best for |
| --- | --- | --- |
| Modern analyst workspace | `python modern_main.py` | Browser workflow, richer charts, live capture, topology, endpoint security, and LLM guidance |
| Classic PySide6 desktop | `python main.py` | Native workflow, custom rules, enforced blocklist, and durable investigation evidence |

Both interfaces use the same SQLite database by default: `data/lightweight_ids.db`.

## Highlights

- Import `.pcap`, `.pcapng`, and `.cap` files, or capture traffic from a local interface.
- Apply configurable built-in and custom detection rules through the normal detection engine.
- Inspect alert evidence and all related stored packets before confirming or ignoring an alert.
- Prioritize hosts with composite risk scores, asset importance, baselines, and attack-chain context.
- Manage assets and preserve analyst investigations with evidence snapshots.
- Explore real packet-derived host connections in Host Explorer and Network Topology.
- Tune rule thresholds and time windows with SQLite-backed persistence.
- Maintain IP and port blocklist entries; Windows Firewall enforcement is attempted when supported and authorized.
- Review Windows security events, process inventory, file-integrity state, and local system health.
- Detect sustained CPU or supported NVIDIA GPU utilization as a review signal for possible cryptomining or malware.
- Export persisted alerts and investigation evidence for analysis and reporting.
- Follow the system light/dark theme, adjust font size, and persist wallpaper and overlay-pet preferences.
- Optionally request English or Chinese defense guidance from an OpenAI-compatible LLM endpoint.

## Requirements

- Python 3.11 or newer
- Packages from `requirements.txt`
- Windows Npcap and suitable privileges for live capture on Windows
- Node.js 22.12 or newer for the modern frontend
- An NVIDIA driver exposing `nvidia-smi` for GPU utilization monitoring; CPU monitoring works without it

HTTPS payloads are not decrypted from packet captures. TLS analysis is limited to metadata and fingerprint risk. See [HTTPS Lab Workflow](docs/https_lab_workflow.md) for authorized payload-level testing.

## Installation

Create or activate a Python 3.11+ environment, then install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

The modern launcher installs missing frontend packages on its first run. To install them manually:

```powershell
cd modern_frontend
npm install
cd ..
```

## Run The Modern Workspace

From the project root:

```powershell
python modern_main.py
```

The launcher initializes the database, starts the local API at `http://127.0.0.1:8787`, starts the frontend at `http://127.0.0.1:4173`, and opens the browser.

Useful options:

```powershell
python modern_main.py --no-browser
python modern_main.py --skip-install
python modern_main.py --database .\data\custom_ids.db
```

Press `Ctrl+C` in the launcher terminal to stop services started by that launcher.

Modern Assets and Investigations create, read, edit, and delete records through local API v6 and persist them in SQLite. The classic desktop additionally supports adding/removing alert evidence snapshots and investigation HTML export.

## Run The Classic Desktop

```powershell
python main.py
```

The classic application provides Dashboard, Traffic Monitor, Host Explorer, Alert Center, Investigations, Assets, Rule Management, Reports, Settings, and Personalization pages.

## Quick Demo

Generate the deterministic demonstration capture:

```powershell
python -m scripts.generate_demo_pcap
```

Then import `sample_data/demo_attack_chain.pcap`. The classic Traffic Monitor can also generate and load it through `Load demo data` when necessary. See the [Demo Guide](docs/demo_guide.md).

## Reset Behavior

`Reset statistics` clears runtime packet, alert, baseline, and Windows security-event records and resets their counters. It also clears Reports and Event Timeline runtime data.

Assets, investigations, and investigation evidence snapshots are intentionally preserved. Delete or replace the SQLite database only when a completely new application state is required.

## Detection And Response Boundaries

- A detection alert is evidence for analyst review, not proof that a host is compromised.
- Sustained CPU/GPU rules may also match legitimate compilation, rendering, gaming, or compute workloads.
- Offline packet files describe historical traffic and cannot be blocked retroactively.
- A blocklist entry rejects future matching traffic only when its enforcement status is `Active`.
- Automatic enforcement currently uses Windows Firewall and may require administrator privileges.
- The application does not decrypt HTTPS payloads, install interception certificates, exploit targets, or scan public systems.

## Tests

Backend and PySide6 tests:

```powershell
python -m pytest
```

Modern frontend tests and production build:

```powershell
cd modern_frontend
npm test
npm run build
npm run test:e2e
```

Keep the frontend running at `http://127.0.0.1:4173` before the Playwright command.

## Documentation

- [Documentation Index](docs/README.md)
- [User Manual](docs/user_manual.md)
- [System Design](docs/system_design.md)
- [HTTPS Lab Workflow](docs/https_lab_workflow.md)
- [Protection Workflow](docs/protection_workflow.md)
- [Demo Guide (Chinese)](docs/demo_guide.md)

## Repository Layout

| Path | Purpose |
| --- | --- |
| `capture/`, `parser/` | Live capture, filtering, pcap loading, and packet normalization |
| `detection/` | Detection engine, rules, analysis, baselines, and noise reduction |
| `storage/`, `models/` | SQLite migrations, repositories, and shared records |
| `ui/` | Classic PySide6 application |
| `modern_frontend/`, `modern_ui/` | React analyst workspace and local Python API |
| `endpoint_security/`, `protection/` | Host telemetry, security events, integrity checks, and blocklist enforcement |
| `report/` | Report and investigation export |
| `scripts/`, `sample_data/` | Deterministic demo generation and sample material |
| `tests/` | Python and integration tests |

## License

See [LICENSE](LICENSE).
