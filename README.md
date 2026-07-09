# Lightweight IDS

Lightweight IDS is a course-oriented local intrusion detection system built with Python 3.11, PySide6, Scapy, SQLite and pytest. It supports offline pcap analysis, live capture, rule-based detection, alert management, custom rules, blacklist management and report export.

The project is intended for defensive coursework, authorized lab traffic and local experiments. It does not include exploit code, public-target scanning or unauthorized interception.

## Key Features

- PySide6 desktop GUI with Dashboard, Traffic Monitor, Alert Center, Rule Management, Reports and Settings pages.
- Offline pcap import for `.pcap`, `.pcapng` and `.cap` files.
- Live capture through local network interfaces. On Windows this may require Npcap and administrator privileges.
- Authorized decrypted HTTP log import from local JSONL or CSV files. This workflow only reads plaintext HTTP records that the user is permitted to inspect.
- Standardized `PacketRecord` parsing for IP, ports, protocol, length, TCP flags, DNS and HTTP fields.
- Detection engine with cooldown, alert noise reduction, whitelist handling, asset-importance adjustment and minimum severity filtering.
- Built-in rules for scans, floods, sensitive ports, blacklist matches, brute force, DNS anomalies, suspicious HTTP requests, SQL injection, XSS, command execution, advanced web attacks, lateral movement, TLS risks, ML anomaly scoring, flow anomaly detection, signature matching, baseline deviation, bandwidth spikes and session duration anomalies.
- Advanced Web attack coverage for path traversal, command injection, SSRF, local/remote file inclusion, XXE, SSTI, CRLF injection, LDAP/XPath injection, deserialization, webshell indicators, JNDI probes and sensitive file discovery.
- Flow-level anomaly detection with `FlowFeatureExtractor` and `IsolationForestFlowDetector`. If scikit-learn is unavailable, the project falls back to a deterministic lightweight anomaly detector.
- SQLite persistence for packets, alerts, rules, custom rules, settings and baselines.
- HTML, CSV and JSON report export.
- Unit tests for parsing, detection rules, database repositories, reports, decrypted HTTP import, flow features, signature matching and TLS metadata.

## Install

Recommended project-local Conda environment:

```powershell
.\.conda\Lightweight-IDS\python.exe -m pip install -r requirements.txt
```

Any Python 3.11+ environment can also be used:

```powershell
python -m pip install -r requirements.txt
```

## Run

From the project root:

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

Or, if your environment is already activated:

```powershell
python main.py
```

The first launch initializes:

```text
data/lightweight_ids.db
```

## Tests

```powershell
.\.conda\Lightweight-IDS\python.exe -m pytest
```

## Windows Capture Notes

Offline pcap analysis does not require administrator privileges. Live capture depends on local network-interface permissions; on Windows, install Npcap and run the application with administrator privileges if capture fails.

Live capture only passively receives local interface traffic. It does not scan, attack or actively access any target.
