# Nightly Improvement Execution Plan

## Goal

Use the remaining development time on changes that make the IDS more usable in real local experiments, without overstating HTTPS payload visibility.

## Priorities

1. Improve live capture smoothness and controllability.
2. Reduce noisy encrypted/background traffic before it reaches the parser.
3. Make packet table rendering predictable during long captures.
4. Keep UI text English and keep dependencies light.
5. Preserve existing rule, parser, and database schema behavior unless a small integration hook is necessary.

## Phase 1: Live Capture Control

### Feature: Capture filter presets

Add a filter mode on the Traffic Monitor page:

- `All traffic`
- `Web + DNS`
- `Internal TCP/UDP`
- `Custom`

For preset modes, populate a BPF-style filter string automatically. For `Custom`, allow the user to edit the filter manually.

Expected benefit:

- Less packet volume reaches Scapy callbacks.
- The UI and SQLite write path receive fewer irrelevant packets.
- Local experiments can focus on traffic that the project can actually analyze.

### Feature: Display row limit control

Add a small numeric control for visible packet rows.

Expected benefit:

- Users can choose a larger visible window for offline review.
- During live capture, the table remains bounded and responsive.

### Feature: Auto-scroll toggle

Add an `Auto-scroll` toggle for the packet table.

Expected benefit:

- Users can keep watching the newest packets during capture.
- Users can turn it off when manually reviewing earlier rows.

## Phase 2: Capture Pipeline Hardening

### Feature: Batched live-capture emissions

Keep the live-capture batching path:

- Flush by packet count.
- Flush by idle interval.
- Do not emit one Qt signal per packet.

Expected benefit:

- Fewer UI thread wakeups.
- Fewer small SQLite transactions.

### Feature: Parser exception isolation

Keep single-packet parsing errors from killing the capture thread.

Expected benefit:

- One unusual packet does not stop the whole live capture.

## Phase 3: HTTPS Lab Workflow

### Feature: Decrypted log helper docs

Document the practical lab workflow:

- Capture encrypted pcap for metadata and flow behavior.
- Use authorized decrypted HTTP logs for payload-level SQLi/XSS/command checks.
- Do not claim HTTPS decryption.

Expected benefit:

- The project is easier to explain honestly in a report or demo.

## Phase 4: UI Polish

### Feature: Action feedback

For long or destructive actions:

- Provide visible status text.
- Show clear error dialogs when an operation fails.

Expected benefit:

- Fewer "button did nothing" moments.

### Feature: Default pcap path reuse

Persist the Settings page default pcap path and use it as the starting location for `Import pcap`.

Expected benefit:

- Local experiments need fewer repeated path-selection steps.
- The import workflow still uses the normal file picker and DetectionEngine path.

## Current Implementation Target

This pass implements Phase 1, reinforces Phase 2, and adds one Phase 4 workflow improvement:

- Capture filter presets in `PacketPage`.
- BPF filter support in `LiveCapture`.
- User-configurable packet table visible row limit.
- Packet table auto-scroll toggle.
- Persisted default pcap path selection in `SettingsPage`.
- Default pcap dialog location reuse in `PacketPage`.
- Validation through pytest and offscreen UI smoke tests.
