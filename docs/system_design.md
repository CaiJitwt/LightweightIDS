# System Design

## Architecture

Lightweight IDS is a local desktop IDS made of five main layers:

- GUI: PySide6 pages for dashboard, traffic monitoring, alerts, rules, reports and settings.
- Capture and import: pcap loading, live capture and authorized decrypted HTTP log loading.
- Parsing: Scapy packet parsing plus decrypted HTTP record conversion into `PacketRecord`.
- Detection: rule engine, built-in rules, custom rules, signatures, baseline checks and ML-style anomaly scoring.
- Persistence and reporting: SQLite repositories, schema migrations and HTML/CSV/JSON report output.

## Detection Flow

1. A pcap file, live packet or authorized decrypted HTTP log is loaded.
2. Raw traffic is converted into `PacketRecord`.
3. `DetectionEngine` builds active rules from database rule records and custom rules.
4. Each rule emits zero or more `AlertRecord` objects.
5. Noise reduction applies whitelist, asset importance, minimum severity and cooldown filtering.
6. Packets and alerts are persisted to SQLite and shown in the GUI.

## Rule Coverage

The merged rule set includes both branches' work:

- Core network rules: port scan, SYN flood, ICMP flood, sensitive port access and blacklist matches.
- Application rules: suspicious HTTP, SQL injection, XSS, malicious command and advanced Web attack detection.
- Advanced Web coverage: path traversal, command injection, SSRF, file inclusion, XXE, SSTI, CRLF injection, LDAP/XPath injection, deserialization, webshell indicators, JNDI probes and sensitive file discovery.
- Behavior rules: abnormal outbound traffic, lateral movement, host scan, baseline deviation, bandwidth spike and session duration anomaly.
- ML and signature rules: packet-level anomaly score, flow-level anomaly score, external signatures and TLS fingerprint risk.

## Data Model

SQLite stores packets, alerts, built-in rule settings, custom rules, baselines and key-value settings. Baseline records track per-source activity windows including packet counts, connection counts, destination diversity, byte volume and internal-to-external ratio.

## Authorized Decrypted HTTP Analysis

The decrypted HTTP workflow imports local JSONL or CSV records that already contain plaintext HTTP data from an authorized lab or defensive source. The application does not install certificates or perform interception. Imported records are converted into HTTP `PacketRecord` objects so existing SQL injection, XSS, suspicious HTTP, malicious command and advanced Web rules can run offline.
