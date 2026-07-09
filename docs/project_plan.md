# Lightweight IDS Project Plan

## Project Goal

Lightweight IDS is a course-oriented desktop intrusion detection system. Its goal is to help students understand IDS data flow and detection logic through local traffic import, live capture, rule-based detection, alert management, statistics and report export.

## Completed Features

1. Desktop GUI with Dashboard, Traffic Monitor, Alert Center, Rule Management, Reports and Settings pages.
2. Data collection through pcap import and Scapy-based live capture.
3. Protocol parsing for IPs, ports, protocol, TCP flags, DNS queries, HTTP fields, payload summaries and TLS handshake identification.
4. SQLite storage for packets, alerts, built-in rules, custom rules, settings and baselines.
5. Detection rules for port scan, SYN flood, ICMP flood, sensitive ports, blacklist matches, brute force, DNS anomaly, suspicious HTTP, SQL injection, XSS, malicious command, abnormal outbound traffic, lateral movement, host scan, TLS fingerprint risk, packet anomaly scoring, advanced Web attacks, flow anomaly detection, signature matching, baseline deviation, bandwidth spike and session duration anomaly.
6. Custom rules by protocol, IP, port and keyword.
7. Alert management with filtering, search, detail viewing, status updates, ignore/delete handling and CSV export.
8. Dashboard statistics for protocol distribution, severity distribution, top IPs, top ports, attack-chain stages, anomaly score trends and attack-chain timelines.
9. Attack-chain analysis that correlates scan, exploitation, execution, C2 and lateral movement stages by source IP.
10. False-positive reduction through whitelist handling, asset-importance adjustment and duplicate alert cooldown.

## Phase Status

- Phase 1: project skeleton, data models, database and empty GUI pages: complete.
- Phase 2: pcap import, Scapy parsing and packet-table display: complete.
- Phase 3: detection engine, rule base and core rules: complete.
- Phase 4: Alert Center, SQLite alert persistence, report export and `.gitignore`: complete.
- Phase 5: Rule Management, statistics charts and live capture: complete.
- Extension phase: signatures, behavior anomalies, TLS fingerprinting, anomaly scoring, attack-chain analysis, false-positive reduction, baselines, flow anomaly detection and GUI analysis views: complete.

## Current Recommendation

Before committing, run the test suite and manually open the GUI once to verify pcap import, rule saving and any Windows-specific capture dependency behavior in the local environment.
