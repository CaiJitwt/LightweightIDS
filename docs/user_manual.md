# Lightweight IDS User Manual

## Start The Application

Recommended:

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

With an already activated Python 3.11+ environment:

```powershell
python main.py
```

Avoid running the project with a system Python that does not have PySide6, Scapy and the other dependencies installed.

## Traffic Monitor

Use `Import pcap` to select a local `.pcap`, `.pcapng` or `.cap` file. The application parses packets, saves them to SQLite, applies enabled detection rules and displays generated alerts.

Use `Import decrypted HTTP log` only for local JSONL or CSV records that already contain plaintext HTTP data from an authorized lab or defensive source. This enables SQL injection, XSS, suspicious HTTP, malicious command and advanced Web attack rules to inspect HTTP content offline.

For live capture, click `Refresh interfaces`, choose an interface or the default interface, and click `Start capture`. On Windows, install Npcap and run as administrator if capture fails.

## Alert Center

The Alert Center lists generated alerts with severity, type, source, destination, protocol, description, evidence and status. Use the available actions to review, ignore or update alert status.

## Rule Management

Built-in rules can be enabled or disabled, and their thresholds and time windows can be edited. Custom rules support optional protocol, source IP, destination IP, source port, destination port and keyword conditions. Empty fields mean no restriction.

Blacklist entries are one IP address per line. Save changes before importing new traffic or starting live capture.

## Reports

Use the Reports page to export detection results as HTML, CSV or JSON. Reports summarize packets, alerts, severity distribution, alert types and key traffic statistics.

## Settings

The Settings page stores application options such as log level. Changes are saved to SQLite and reused on later launches.
