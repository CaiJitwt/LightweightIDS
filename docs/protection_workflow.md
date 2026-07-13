# Protection and Evidence Workflow

## Enforcement boundary

The application is primarily a network IDS. Offline pcap imports can only analyze historical traffic and cannot reject it.

For live protection on Windows, an enforced blocklist entry creates Windows Firewall rules through `netsh advfirewall`. Administrator privileges are normally required. The application records one of these states:

- `Active`: Windows Firewall accepted every required rule.
- `Failed`: the entry is stored but the firewall did not accept it.
- `Unsupported`: automatic firewall enforcement is not available on the current platform.
- `Pending`: the entry has not completed an enforcement attempt.

Never interpret `Failed` or `Unsupported` as blocked traffic. Rule Management provides retry and removal actions.

## Adding evidence-based blocks

In Alert Center, selecting an alert displays every packet correlated to its rule window. Right-click a packet to block its source IP, destination IP, source port, or destination port. The action asks for confirmation before changing firewall policy.

Window-based rules use broader correlation scopes:

- Host scan and lateral movement correlate by source host.
- Port scan and flood alerts correlate by source and target.
- Brute force also correlates by destination port.
- Stateless payload rules correlate the packet endpoints and ports within a short window.

## Web attack detection hardening

Payload matching applies bounded canonicalization before signatures:

- Unicode NFKC normalization.
- Up to two URL/HTML decoding rounds.
- Percent-Unicode and repeated hexadecimal escape decoding.
- Limited printable Base64 token decoding.
- SQL inline-comment removal as an additional matching view.

The implementation limits input to 16 KB and at most 12 canonical variants. This follows OWASP guidance to normalize untrusted input while avoiding unbounded regular-expression or decoding work. It improves IDS visibility but does not replace prepared statements, strict allowlist validation, contextual output encoding, least privilege, or secure application design.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- https://github.com/digininja/DVWA
