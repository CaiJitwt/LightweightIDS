# Lightweight IDS Modern Frontend

This React frontend provides the modern analyst workspace alongside the PySide6 application. It remains usable with an explicitly labelled offline preview, but uses the local Python API for persisted dashboard statistics, alerts, related packets, host profiles, live packet capture, endpoint posture checks, file-integrity scans, and process inventory whenever the API is available.

## Run

From the project root, start the local API and frontend together:

```powershell
python modern_main.py
```

The launcher installs missing frontend packages on the first run, starts both services, and opens the browser. Press `Ctrl+C` in the launcher terminal to stop the services it started. Use `python modern_main.py --no-browser` when automatic browser opening is not wanted.

The two-service development workflow remains available when needed:

```powershell
python -m modern_ui.local_api
cd modern_frontend
npm install
npm run dev
```

Open `http://127.0.0.1:4173`.

The local API is intentionally bound to `127.0.0.1:8787`. Live capture requires Scapy, Npcap on Windows, and any permissions required by the selected adapter. The browser never captures packets directly.

## LLM guidance

Settings accepts an OpenAI-compatible Base URL, model, and API key. The Base URL and model remain in browser local storage; the key is kept in browser session storage. An alert is sent only when the analyst presses `Generate defense guidance`; normal traffic is not sent automatically. TLS records remain metadata or fingerprint evidence only.

## Verify

```powershell
npm test
npm run build
# Keep `npm run dev` running in another terminal before this command.
npm run test:e2e
```

The workspace includes Dashboard, Traffic Monitor, Host Explorer, Alert Center, Investigations, Assets, Rule Management, Reports, Event Timeline, Network Topology, System Health, Endpoint Security, Settings, and Personalization. The Dashboard, Host Explorer, and Alert Center use the local API rather than mock data when it is running; status labels make the offline preview explicit. Selecting an alert lists its matching stored packets, and selecting a packet shows its full stored metadata. The prototype does not decrypt HTTPS payloads: TLS is shown only as metadata or fingerprint evidence.
