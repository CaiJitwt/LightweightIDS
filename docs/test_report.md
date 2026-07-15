# Test And Verification Guide

[Documentation Index](README.md) | [Project README](../README.md)

## Scope

The Python test suite covers storage migrations and repositories, packet parsing, filters, pcap/decrypted-HTTP import, built-in and custom rules, attack-chain and host analysis, reports, blocklist behavior, endpoint monitoring, the local API, and selected offscreen PySide6 workflows.

The modern frontend suite covers API-backed views, settings, reset behavior, navigation, and component rendering. Playwright checks the primary dashboard and alert workflow on desktop and mobile viewports.

## Python Tests

From the project root:

```powershell
python -m pytest
```

Use the intended environment's interpreter explicitly when multiple Python installations are present.

## Frontend Unit Tests

```powershell
cd modern_frontend
npm test
```

## Production Build

```powershell
cd modern_frontend
npm run build
```

The build runs TypeScript validation before producing `modern_frontend/dist/`.

## Browser Tests

Keep the frontend available at `http://127.0.0.1:4173`, then run:

```powershell
cd modern_frontend
npm run test:e2e
```

## Manual Capture Checks

Automated tests cannot fully reproduce every Npcap adapter and permission combination. Before a release, verify:

1. interface refresh and selection;
2. empty-filter live capture;
3. filter validation and immediate table filtering;
4. pause, resume, and stop behavior;
5. newest-first packet ordering and packet details;
6. alert generation and related-packet correlation;
7. reset behavior across Dashboard, Reports, Event Timeline, topology, and security events.

## Optional Features

GPU telemetry tests use injected samples and do not require an NVIDIA GPU. At runtime, the GPU rule remains inactive when `nvidia-smi` is unavailable. HTTPS payload decryption is intentionally outside the test scope because the application does not provide it.
