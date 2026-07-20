# Runtime Hardening Plan

> **Status: historical planning record.** Some items may be implemented or superseded. Use the [documentation index](README.md), user manual, and current source code for runtime behavior.

## Objective

Keep long pcap imports and live captures responsive while making capture health visible to the operator.

## Observed Bottlenecks

1. Packet and alert batches were written to SQLite from the GUI thread.
2. Packet and alert writes used separate connections and transactions for each batch.
3. Alert details loaded and converted up to 10,000 packets before scanning for one match.
4. Dashboard baseline refresh opened and committed one SQLite connection per host.
5. Alert search refreshed the entire table on every keystroke and recalculated every row height.

## Implementation

### Background persistence

- Persist packet and alert batches inside the import or capture worker.
- Store each packet and alert batch in one SQLite transaction.
- Emit only display-ready rows and saved counters back to the GUI thread.
- Continue past isolated parser or rule failures and report the skipped count.
- Stop active import and capture workers cleanly when the application closes.

### SQLite concurrency

- Use WAL journal mode so dashboard reads can coexist with capture writes.
- Configure a 10-second busy timeout for short write contention.
- Add indexes for alert filtering, trend aggregation, feedback aggregation, dashboard summaries, and packet-to-alert matching.

### Alert Center responsiveness

- Limit one table refresh to the newest 2,000 matching alerts.
- Debounce keyword search input by 250 milliseconds.
- Use a fixed row height and suspend table repainting during bulk replacement.
- Query the matching packet directly by timestamp, endpoints, ports, and protocol.
- Preserve the selected alert across refreshes when it remains in the result set.

### Dashboard refresh cost

- Upsert all baseline records through one connection and one transaction.

### Runtime settings

- Persist packet storage, live detection, alert cooldown, and log level controls.
- Read capture settings when a new import or live capture starts.
- Allow packet display and detection to continue when packet database storage is disabled.
- Allow live capture to operate as a traffic viewer when live detection is disabled.

## Validation

- Repository tests cover WAL and indexes, atomic traffic batches, exact packet matching, and batch baseline updates.
- The complete pytest suite must pass.
- Offscreen PySide smoke tests must instantiate the affected pages and exercise table refresh behavior.
- UI text introduced by this pass remains English.

## Deferred Work

- Database retention policies and archival need an explicit product decision because they delete or move historical data.
- Full packet payload storage is intentionally not added; current records retain parsed fields and a bounded summary.
- HTTPS payload inspection still requires authorized decrypted HTTP logs. Raw HTTPS captures provide TLS metadata only.
