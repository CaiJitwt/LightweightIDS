# Test Report

## Scope

The test suite covers packet parsing, protocol identification, database repositories, report generation, built-in rules, custom rules, decrypted HTTP import, flow feature extraction, ML flow anomaly fallback behavior, signature matching and TLS metadata handling.

## Merge Validation Focus

This merge preserves tests from both branches:

- `main` coverage for SQL injection, XSS and expanded Web attack detection.
- `develop` coverage for phase one/two/three rule sets, signature rules, decrypted HTTP loading, baseline detection, flow anomaly detection and TLS fingerprint metadata.
- Parser coverage for HTTP extraction, TLS handshake identification, ARP, IPv6, DNS and common protocol naming.

## How To Run

```powershell
.\.conda\Lightweight-IDS\python.exe -m pytest
```

If using an activated Python 3.11+ environment:

```powershell
python -m pytest
```

## Expected Result

All tests should pass in a prepared environment with the project dependencies installed from `requirements.txt`. Optional ML behavior is designed to fall back to a deterministic local detector when scikit-learn is unavailable.
