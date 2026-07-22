# Lightweight IDS System Design

[Documentation Index](README.md) | [Project README](../README.md)

## 1. System Context

Lightweight IDS is a local, user-mode network and endpoint analysis application. It has two presentation layers over shared Python services and the same default SQLite database:

- the classic PySide6 desktop in `ui/`, started by `main.py`;
- the React analyst workspace in `modern_frontend/`, connected to `modern_ui/local_api.py` and started together by `modern_main.py`.

The modern API binds to `127.0.0.1` and is not intended to be exposed as a remote multi-user service.

Local API v8 includes the `analyst-workflow-v1` capability. Assets and investigations use REST-style GET, POST, PUT, and DELETE routes backed by the existing repositories and SQLite tables.

## 2. Major Layers

| Layer | Main paths | Responsibility |
| --- | --- | --- |
| Presentation | `ui/`, `modern_frontend/` | Analyst interaction, tables, charts, navigation, and settings |
| Local API orchestration | `modern_ui/`, `modern_main.py` | Browser-to-Python boundary, capture/import sessions, API compatibility, protected settings |
| Capture and import | `capture/`, `modern_ui/capture_session.py`, `modern_ui/pcap_import.py` | Interfaces, filters, live packets, pcap loading, authorized HTTP-log import |
| Parsing | `parser/` | Convert Scapy packets and authorized HTTP records into `PacketRecord` |
| Detection and analysis | `detection/` | Built-in/custom rules, engine, noise reduction, attack chains, trends, baselines, host risk |
| Endpoint security | `endpoint_security/`, `modern_ui/security_event_monitor.py` | Runtime health, Windows events, process inventory, posture, file integrity |
| Protection | `protection/` | Structured blocklist and optional Windows Firewall enforcement |
| Persistence | `storage/`, `models/` | SQLite migrations, repositories, and shared records |
| Reporting | `report/` | Alert reports and durable investigation exports |

## 3. Packet Analysis Flow

1. A source produces traffic: live capture, pcap import, deterministic demo pcap, or authorized plaintext HTTP log.
2. The parser normalizes the source into `PacketRecord` objects.
3. Packets are persisted when saving is enabled.
4. `DetectionEngine` loads enabled built-in rules, custom rules, settings, asset importance, and active blocklist entries.
5. Rules evaluate packets or bounded windows of packet history and emit `AlertRecord` candidates.
6. Noise reduction applies cooldown, whitelist, minimum severity, asset importance, and related controls.
7. Accepted alerts are stored in SQLite and become available to Dashboard, Alert Center, Host Explorer, Reports, and Event Timeline.

The demo generator follows the same parser and Detection Engine path; it does not insert synthetic alerts directly.

## 4. Detection Model

The rule set covers:

- scans, floods, brute force, sensitive ports, and blacklist matches;
- suspicious HTTP, SQL injection, XSS, malicious commands, and advanced Web signatures;
- DNS anomalies, TLS metadata/fingerprint risk, abnormal outbound traffic, and C2-like behavior;
- lateral movement, SMB administrative-share access, RDP activity, and Windows security events;
- baseline deviation, flow/packet anomaly scoring, bandwidth spikes, and long sessions;
- sustained CPU and supported GPU load as endpoint review signals.

Threshold and time-window values are stored with built-in rule records. Runtime monitors reload current rule settings, so persisted changes apply without replacing rule definitions.

No single rule proves compromise. Resource-load, anomaly, and heuristic alerts require analyst validation.

## 5. Analysis Services

- `AttackChainAnalyzer` orders existing rule stages and correlates compatible alert sequences.
- `HostRiskScorer` combines severity, attack-chain, baseline, and optional asset-importance components into a score capped at 100.
- `AlertTrendAnalyzer` uses repository time buckets and identifies spikes above historical mean plus two standard deviations.
- `HostProfileService` merges packet, alert, baseline, and asset records into host, connection, alert, and timeline views.

These services read persisted records and do not bypass the Detection Engine.

## 6. Endpoint And Resource Monitoring

The Windows security-event monitor reads selected event channels and uses cursor records to avoid replaying the complete history on every poll. Relevant events can be linked to generated alerts.

Runtime health reads CPU, memory, disk, platform, and sensor status. NVIDIA GPU utilization is queried through `nvidia-smi` when available. The resource monitor tracks continuous above-threshold time and emits at most one alert per high-load episode until the metric recovers.

Process inventory, posture checks, and file-integrity baselines are user-mode operations. The project does not install a driver or kernel module.

## 7. Persistence Model

SQLite migrations use `CREATE TABLE/INDEX IF NOT EXISTS` and preserve existing databases. Current tables include:

- `packets`, `alerts`, `baselines`;
- `rules`, `custom_rules`, `settings`;
- `assets`;
- `investigations`, `investigation_evidence`;
- `blocklist_entries`;
- `security_events`, `security_event_cursors`, `security_event_alert_links`.

Investigation evidence stores an alert snapshot instead of only a foreign-key reference. This keeps analyst evidence after the source alert is deleted or runtime statistics are reset.

## 8. Reset Model

Reset is a coordinated runtime operation:

1. active live capture and pcap import must be stopped;
2. resource and security-event monitors pause;
3. packet, alert, baseline, and security-event tables and counters are cleared;
4. capture/import buffers and monitor statistics are reset;
5. previously running monitors restart;
6. frontend views refresh from the empty persisted state.

Assets, investigations, and evidence snapshots remain intact by design.

## 9. Protection Boundary

Blocklist entries are persisted independently from detection alerts. On Windows, `WindowsFirewallEnforcer` uses `netsh advfirewall` to create or remove operating-system rules. The repository records enforcement status and error details.

Only `Active` means the operating system accepted the block. Offline pcap analysis cannot reject past traffic, and unsupported or failed entries must not be presented as enforced.

## 10. LLM Integration

LLM guidance is analyst initiated. The local API builds a bounded prompt from the selected alert and sends it to an OpenAI-compatible endpoint only after explicit action.

Base URL and model are stored in SQLite. On Windows, the API key is protected with current-user DPAPI, never returned in settings responses, and never rendered as plaintext after saving. The language option adds an English or Simplified Chinese response instruction.

LLM output is advisory and does not automatically change rules, firewall policy, or alert status.

## 11. HTTPS Boundary

Raw TLS captures provide endpoint, timing, protocol, handshake, and fingerprint metadata only. The system does not decrypt HTTPS payloads or install interception certificates.

Payload-level Web-rule testing uses authorized plaintext HTTP records exported from a lab proxy or application gateway and imported separately.
