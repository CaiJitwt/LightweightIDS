# Lightweight IDS User Manual

[English](user_manual.md) | [简体中文](user_manual.zh-CN.md) | [Documentation Index](README.md)

## 1. Choose An Interface

Lightweight IDS provides two supported interfaces over the same default SQLite database.

### Modern Analyst Workspace

```powershell
python modern_main.py
```

Use this interface for the browser-based analyst workspace, including richer charts, live capture, pcap import, host analysis, topology, Windows security events, endpoint posture, and optional LLM defense guidance.

The launcher starts a local API on `127.0.0.1:8787` and a frontend on `127.0.0.1:4173`. If the page says `Offline preview`, restart `modern_main.py`; preview data is not persisted project data.

### Classic PySide6 Desktop

```powershell
python main.py
```

Use this interface for the native Qt workflow, deterministic demo loading, authorized decrypted HTTP-log import, custom-rule editing, enforced blocklist management, and investigation evidence snapshots.

## 2. First Run And Data

The default database is created automatically at:

```text
data/lightweight_ids.db
```

Database migrations are incremental and preserve existing records. Built-in rules are inserted when missing without overwriting thresholds and enabled states already saved by the user.

## 3. Traffic Monitor

### Import A Packet Capture

Choose a `.pcap`, `.pcapng`, or `.cap` file from the interface. Imported packets are parsed, evaluated by enabled rules, and persisted when packet saving is enabled. Alerts are produced through the Detection Engine rather than inserted as demo records.

The modern workspace uses the browser file picker and sends the selected file to the local API. The classic desktop uses a native file chooser.

### Live Capture

1. Install Npcap on Windows.
2. Start the application with sufficient capture permissions.
3. Refresh interfaces and select an adapter.
4. Optionally enter and validate a capture/display filter.
5. Select `Start capture`.
6. Use Pause, Resume, or Stop as needed.

The browser does not capture packets itself. `modern_main.py` runs the Python capture service locally.

Recent packets appear first. Select a packet to inspect its full stored metadata and summary.

### Demo Data

Generate the deterministic demonstration pcap with:

```powershell
python -m scripts.generate_demo_pcap
```

Import `sample_data/demo_attack_chain.pcap`. In the classic desktop, `Load demo data` generates the file automatically if it is missing.

### Authorized Decrypted HTTP Logs

The classic desktop can import authorized JSONL or CSV records that already contain plaintext HTTP request data. This is intended for local proxy or application-gateway exports from a lab you control. See [HTTPS Lab Workflow](https_lab_workflow.md).

The application does not decrypt HTTPS traffic from a raw pcap.

## 4. Dashboard

The Dashboard summarizes packet counts, open alerts, high-risk hosts, severity distribution, traffic/alert trends, and alert detection rate. The modern Dashboard refreshes periodically when Auto-refresh is enabled.

`Reset statistics` clears:

- packets and live packet buffers;
- alerts and alert counters;
- baseline records;
- Windows security-event records;
- pcap-import and capture-session counters;
- Reports and Event Timeline runtime content.

It intentionally preserves assets, investigations, and investigation evidence snapshots.

## 5. Alert Center

Select an alert to review severity, rule, endpoints, description, evidence, and analyst status. Related packets are matched using the alert endpoints and rule time window; aggregate detections such as scans, floods, and lateral movement may therefore show multiple packets.

Use packet selection to inspect full stored metadata. Confirm or ignore an alert only after checking the evidence. Status changes affect analyst workflow but do not rewrite the original packet.

The classic desktop can add an alert to an investigation and can open a packet context menu to add its source IP, destination IP, source port, or destination port to the enforced blocklist.

## 6. Host Explorer And Assets

Host Explorer combines IP addresses observed in packets, alerts, baselines, and assets. It provides:

- composite host risk and its scoring reasons;
- inbound and outbound activity;
- peers, protocols, ports, and packet counts;
- alerts involving the host as source or destination;
- a merged host timeline.

Assets assign a display name, controlled role, importance from 0 to 100, and notes to a unique IP address. Asset importance affects analyst prioritization and host-risk scoring; it does not create a whitelist entry. The modern and classic interfaces both persist asset changes in the shared SQLite database; an asset IP cannot be changed while editing.

## 7. Rule Management

Built-in rules can be enabled or disabled. Their threshold and time-window values are persisted in SQLite and apply to future imports and capture sessions; existing alerts are not recalculated automatically.

The sustained CPU and GPU rules default to 90 percent for 300 seconds. They are review signals for possible cryptomining or malware, but legitimate intensive workloads can also trigger them. GPU monitoring requires supported NVIDIA `nvidia-smi` telemetry.

The classic desktop additionally supports custom rules with protocol, source/destination IP, source/destination port, keyword, severity, and description fields. Empty fields mean no restriction; port `0` means any port.

## 8. Blocklist And Enforcement

Classic Rule Management stores structured IP and port blocklist entries. Alert-related packet menus provide shortcuts for adding fields.

On Windows, the application attempts to create corresponding Windows Firewall rules. Administrator privileges may be required.

- `Active`: the operating system accepted the firewall rule.
- `Failed`: the entry is saved, but enforcement did not succeed.
- `Unsupported`: automatic enforcement is unavailable on the current platform.

Offline pcap analysis cannot reject historical traffic. See [Protection Workflow](protection_workflow.md).

## 9. Investigations And Reports

Investigations organize a title, host, status, priority, summary, and notes. The modern interface supports persistent create, read, edit, and delete operations through local API v6. Classic investigation evidence is stored as a snapshot, so it remains available after the original alert is deleted or runtime statistics are reset; evidence add/remove and HTML export remain classic-desktop workflows.

Reports export persisted alert data. The modern Reports page supports HTML, CSV, and JSON output. The classic report workflow also summarizes packet and alert statistics. Empty data after a reset is expected and is not replaced with demo alerts.

## 10. Event Timeline And Network Topology

The modern Event Timeline merges persisted packets, alerts, and Windows security events. Resetting statistics clears these runtime entries.

Network Topology derives nodes and edges from current stored or live-capture packet connections. It does not require demo data. When packet storage is disabled, live in-memory connections may still be shown for the active capture session.

## 11. Security Events And Endpoint Security

The modern workspace can monitor selected Windows security-event channels, display relevant events, and generate endpoint alerts from configured rules. Use Start, Stop, and Refresh on the Security Events page.

Endpoint Security provides read-only host posture, process inventory, and file-integrity baseline/scan workflows. System Health displays local API, sensor, storage, CPU, memory, disk, and supported GPU telemetry.

These modules use user-mode operating-system interfaces; they are not kernel modules.

## 12. Settings, LLM Guidance, And Personalization

Settings controls packet persistence, real-time detection, cooldown, minimum alert severity, security-event monitoring, theme preference, and font size.

The modern LLM panel accepts an OpenAI-compatible Base URL, model, and API key. Base URL and model are stored in SQLite. On Windows, the API key is encrypted for the current user with DPAPI, is never returned to the browser, and is displayed only as a configured/not-configured state. Alert data is sent only when the analyst selects `Generate defense guidance`; the response language can be English or Chinese.

Modern theme, font, wallpaper, and overlay-pet preferences are remembered in browser local storage. The classic desktop copies selected wallpaper and pet files into managed personalization storage and restores them on the next launch.

## 13. Troubleshooting

### Local API unavailable

Stop older launcher/API processes and restart:

```powershell
python modern_main.py
```

Only one compatible service can use ports `8787` and `4173` at a time.

### Live capture has no packets

Verify Npcap installation, adapter selection, permissions, and filter syntax. Try an empty filter first. VPN, loopback, and virtual-machine traffic may use a different adapter from normal Ethernet or Wi-Fi traffic.

### Rule changes do not affect old alerts

Rule settings apply to future analysis. Reimport the pcap or start a new capture after changing a threshold.

### GPU telemetry is unavailable

The GPU rule stays inactive when `nvidia-smi` cannot provide utilization. CPU monitoring continues normally.

### A blocklist entry does not reject traffic

Check that the entry status is `Active`. Retry with administrator privileges and inspect the returned Windows Firewall error if the status is `Failed`.

## 14. Safety Boundary

Use the project only with authorization. TLS alerts represent metadata or fingerprint risk, not decrypted HTTPS content. Detection results require human validation, and no alert by itself proves compromise.
