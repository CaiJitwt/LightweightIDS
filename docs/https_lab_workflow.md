# HTTPS Lab Workflow

This project does not decrypt HTTPS traffic from a raw packet capture. TLS traffic is handled as metadata and fingerprint risk only.

For payload-level testing of SQL injection, XSS, and malicious command patterns, use an authorized lab workflow:

1. Run the target application in a local test environment that you own or have permission to inspect.
2. Use an intercepting proxy or application gateway in that lab to export decrypted HTTP request records.
3. Save the exported records as JSONL or CSV.
4. Import the file with `Import decrypted HTTP log` on the Traffic Monitor page.
5. Use normal pcap import or live capture in parallel for TLS metadata, host behavior, scan patterns, lateral movement indicators, and alert timelines.

## JSONL Format

Each line should be one object:

```json
{"timestamp":"2026-01-01 00:00:00.000","src_ip":"192.168.1.10","dst_ip":"192.168.1.20","src_port":51000,"dst_port":443,"method":"GET","host":"example.test","path":"/search?q=' OR 1=1--","headers":{"User-Agent":"course-lab"},"body_preview":"","source":"authorized lab proxy"}
```

## CSV Columns

Use these headers:

```text
timestamp,src_ip,dst_ip,src_port,dst_port,method,host,path,headers,body_preview,source
```

`headers` may be a JSON object string or simple header lines. `body_preview` should contain only the authorized lab request body preview needed for verification.

## Recommended Demo Split

- Use pcap files for packet counts, network direction, TLS metadata, host scan behavior, and attack-chain continuity.
- Use decrypted HTTP logs for application-layer payload checks.
- Describe TLS-related alerts as TLS metadata or TLS fingerprint risk, not HTTPS payload inspection.
