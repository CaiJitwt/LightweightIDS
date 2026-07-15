# Lightweight IDS Modern Frontend

[Project README](../README.md) | [项目说明](../README.zh-CN.md) | [Documentation](../docs/README.md)

The modern frontend is the browser-based analyst workspace for Lightweight IDS. React renders the interface, while the local Python API performs capture, parsing, detection, persistence, endpoint checks, and protected configuration storage.

The browser never captures packets or accesses SQLite directly.

## Recommended Start

From the project root:

```powershell
python modern_main.py
```

The launcher:

1. initializes the selected SQLite database;
2. starts the local API at `http://127.0.0.1:8787`;
3. installs missing npm packages when necessary;
4. starts Vite at `http://127.0.0.1:4173`;
5. opens the browser unless `--no-browser` is used.

```powershell
python modern_main.py --no-browser
python modern_main.py --skip-install
python modern_main.py --database .\data\custom_ids.db
```

Press `Ctrl+C` in the launcher terminal to stop services it started. If port `8787` contains an older incompatible API, stop that process before launching the current version.

## Development Start

Run the services separately only when frontend development requires it:

```powershell
# Terminal 1, from the project root
python -m modern_ui.local_api

# Terminal 2
cd modern_frontend
npm install
npm run dev
```

## Current Workspaces

- Dashboard with auto-refresh, reset, traffic/alert trends, severity distribution, detection rate, and host risk.
- Traffic Monitor with interface selection, filter validation, live capture controls, pcap import, newest-first packets, and packet details.
- Host Explorer with packet-derived peers, ports, protocols, alerts, timeline, and asset-aware risk.
- Alert Center with evidence, status updates, related-packet lists, full packet metadata, and optional LLM guidance.
- Investigations and Assets interface shells for the planned browser workflow.
- Rule Management for persistent built-in-rule enablement, thresholds, and time windows.
- Reports and Event Timeline backed by persisted runtime records rather than demo alerts.
- Network Topology derived from current stored or live packet connections.
- Windows Security Events, System Health, Endpoint Security, Settings, Personalization, and bilingual Help Center.

Some pages can render an explicitly labeled offline preview when the local API is unavailable. Editing, capture, persistence, reset, and host-security operations require the local API.

### Current API limitation

Local API v5 does not yet expose the Assets or Investigations CRUD routes referenced by those two frontend pages. Use the classic PySide6 desktop for persisted asset, investigation, and evidence-snapshot management until those routes are implemented.

## Live Capture

Live capture is implemented by `modern_ui.capture_session`, not by browser APIs. On Windows it normally requires:

- Scapy from the Python environment;
- Npcap;
- a valid selected interface;
- sufficient capture privileges.

Filters are validated by the local service. Start with an empty filter when diagnosing adapter or permission issues.

## LLM Defense Guidance

Settings accepts an OpenAI-compatible Base URL, model, and API key.

- Base URL and model are persisted in SQLite.
- On Windows, the API key is protected for the current user with DPAPI.
- The API key is never returned to or displayed by the browser after saving.
- Alert data is sent only after the analyst selects `Generate defense guidance`.
- The analyst can request an English or Simplified Chinese response.

## Reset Semantics

Dashboard `Reset statistics` removes packet, alert, baseline, Windows security-event, capture-buffer, and import-counter runtime state. Reports, Event Timeline, topology, and alert badges then refresh from the cleared data.

Assets, investigations, and investigation evidence snapshots are preserved.

## Personalization

Theme preference can follow the operating system or use an explicit light/dark mode. Font size, accent, wallpaper, overlay image, position, size, and opacity are remembered in browser local storage. The overlay is non-interactive and does not intercept primary workspace actions.

## Security Boundary

- TLS is analyzed as metadata or fingerprint risk only; HTTPS payloads are not decrypted.
- Endpoint checks use user-mode operating-system interfaces and are not kernel modules.
- Sustained CPU/GPU alerts are review signals and may represent legitimate intensive workloads.
- Automatic traffic blocking is a separate Windows Firewall workflow exposed by the classic desktop; offline pcap data cannot be blocked retroactively.

## Verify

```powershell
npm test
npm run build
```

For browser checks, keep the frontend running on port `4173`:

```powershell
npm run test:e2e
```

Backend/API tests are run from the project root:

```powershell
python -m pytest
```
