# Modern Frontend and Endpoint Security Implementation Report

## Purpose

The React application in `test/modern_frontend` is being upgraded from a mock
analyst dashboard into a local client for the existing Python IDS pipeline. The
work keeps packet capture, parsing, detection, and persistence in Python and
uses the browser only for operator controls and visual analysis.

The endpoint-security work is intentionally user mode only. It does not install
a kernel driver, hook processes, decrypt HTTPS traffic, or silently alter host
security settings.

## Architecture

```text
React prototype (Vite on 127.0.0.1:4173)
        |
        | HTTP polling, localhost only
        v
modern_ui.local_api (127.0.0.1:8787)
        |
        +-- CaptureSessionService
        |     LiveCapture -> PacketParser -> DetectionEngine -> SQLite
        |
        +-- EndpointPostureService
        |     Windows Firewall / Defender / UAC / BitLocker checks
        |
        +-- FileIntegrityService
              SHA-256 baselines for explicitly selected directories
```

The local service is loopback-only. It exposes no listener on a LAN interface.
There is one capture owner, preventing parallel browser and PySide capture
sessions from opening the same adapter.

## Capture Implementation

1. Add `CaptureSessionService` with start, pause, resume, stop, interface
   enumeration, filter validation, and bounded event buffers.
2. Reuse `LiveCapture`, `PacketFilter`, `PacketParser`, `DetectionEngine`,
   `TrafficRepository`, asset importance, and active blocklist entries.
3. Use batches of 50 packets or 0.5 seconds for database persistence. UI
   clients poll at 750ms and retain only a bounded view window.
4. Show adapter, BPF translation, packets per second, skipped records, saved
   packet count, and alerts. Surface Npcap, permissions, and filter errors as
   clear English messages.
5. Keep offline mock data only as a prototype preview. When the local API is
   reachable, the Traffic Monitor switches to live session data.

## Modern Analyst UI

1. Retain React, TypeScript, TanStack Table, Lucide, Recharts, Vitest, and
   Playwright. Add richer chart libraries only when a concrete interaction
   requires them.
2. Use the existing traffic/alert/host visual language, responsive tables,
   compact controls, keyboard-safe labels, and English visible UI text.
3. The Traffic Monitor receives live capture controls, a rolling throughput
   chart, filter validation, telemetry cards, exports, and offline diagnostics.
4. Alert details gain an opt-in LLM defense-guidance panel.

## LLM Defense Guidance

1. Add a Settings screen for an OpenAI-compatible Base URL, model, and API key.
2. Persist only Base URL, model, and theme preference in local storage. Keep
   the API key in browser session storage; it is removed on browser-session end.
3. Send alert metadata and existing evidence only after the analyst presses
   `Generate defense guidance`. Raw packet streams and unrelated traffic are
   never sent automatically.
4. Prompt for containment, validation, and hardening guidance only. The prompt
   prohibits offensive instructions and makes clear that TLS records are
   metadata/fingerprint evidence, not decrypted HTTPS payloads.
5. The browser sends the request to the loopback Python service, which forwards
   it to the configured endpoint. This avoids browser CORS restrictions while
   keeping the key out of persistent storage.

## Theme Behaviour

1. Theme choices are System, Light, and Dark.
2. System is the default and listens to `prefers-color-scheme` changes at
   runtime.
3. The chosen preference persists locally. The top-bar shortcut explicitly
   selects light or dark without changing the system preference setting.

## User-Mode Endpoint Security Modules

### Endpoint Posture (implemented)

Read Windows firewall profile state, Microsoft Defender service/realtime state,
UAC state, and BitLocker state through PowerShell. Return normalized PASS,
WARNING, FAIL, or UNAVAILABLE checks with a remediation suggestion. The calls
are read-only and return UNAVAILABLE on non-Windows hosts or restricted shells.

### File Integrity Monitoring (implemented)

Create a SHA-256 baseline only for directories explicitly submitted by the
analyst. A later scan reports added, modified, and removed files by hash and
metadata. Baselines are stored locally under `data/endpoint_security` and are
bounded by file-count and file-size limits. No file contents leave the machine.

### Process Inventory (implemented as a read-only extension)

Collect a concise local process list through PowerShell on Windows or a safe
standard-library fallback elsewhere. The initial UI shows process counts and
metadata only; it does not terminate or alter processes.

### Future Interfaces (designed, not claimed as EDR)

* Windows Event Log and Sysmon collection with explicit channel selection.
* Startup persistence inventory and scheduled-task review.
* Defender scan/history integration.
* Optional Windows Firewall enforcement after a human confirmation step.
* Signed report export and investigation evidence links.

## Validation Plan

1. Unit-test filter parsing, capture request validation, bounded event delivery,
   endpoint posture parsing, file integrity baseline/compare logic, and API JSON
   responses with fake capture sources.
2. Run existing Python tests plus frontend Vitest/build and Playwright checks.
3. Smoke-test local API startup, Traffic Monitor service discovery, stopped
   capture state, and settings persistence without an API key.
4. On Windows with Npcap installed, manually confirm interface selection,
   filter validation, start/pause/resume/stop, and graceful errors for missing
   privileges.
