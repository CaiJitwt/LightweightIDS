from __future__ import annotations

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    length INTEGER NOT NULL DEFAULT 0,
    tcp_flags TEXT,
    dns_query TEXT,
    http_method TEXT,
    http_host TEXT,
    http_path TEXT,
    raw_summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unconfirmed',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    threshold INTEGER NOT NULL DEFAULT 1,
    time_window INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'LOW',
    enabled INTEGER NOT NULL DEFAULT 1,
    protocol TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    keyword TEXT,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_RULES = [
    ("PORT_SCAN", "Port scan detection", "scan", "HIGH", 1, 20, 10, "Detects one source IP accessing many ports on the same target in a short time window."),
    ("SYN_FLOOD", "SYN flood detection", "flood", "HIGH", 1, 100, 10, "Detects a high volume of TCP SYN requests in a short time window."),
    ("ICMP_FLOOD", "ICMP flood detection", "flood", "MEDIUM", 1, 50, 10, "Detects a high volume of ICMP packets in a short time window."),
    ("SENSITIVE_PORT", "Sensitive port access", "policy", "MEDIUM", 1, 1, 0, "Detects access to common sensitive service ports."),
    ("BLACKLIST_IP", "Blacklisted IP match", "reputation", "HIGH", 1, 1, 0, "Detects traffic where the source or destination IP matches the local blacklist."),
    ("BRUTE_FORCE", "Brute-force connection detection", "authentication", "HIGH", 1, 10, 10, "Detects repeated connections to SSH, RDP, FTP, MySQL and similar services."),
    ("DNS_ANOMALY", "DNS anomaly detection", "dns", "MEDIUM", 1, 40, 60, "Detects high-frequency DNS queries, long domains and high-entropy random domains."),
    ("HTTP_SUSPICIOUS", "Suspicious HTTP request", "web", "HIGH", 1, 1, 0, "Detects directory traversal, SSRF, file inclusion and suspicious administration paths."),
    ("SQL_INJECTION", "SQL injection detection", "web", "CRITICAL", 1, 1, 0, "Detects SQL injection indicators in HTTP traffic."),
    ("XSS", "XSS detection", "web", "HIGH", 1, 1, 0, "Detects cross-site scripting indicators in HTTP traffic."),
    ("MALICIOUS_COMMAND", "Malicious command detection", "web", "CRITICAL", 1, 1, 0, "Detects suspicious system commands, reverse shells and download-execute patterns."),
    ("ABNORMAL_OUTBOUND", "Abnormal outbound traffic", "behavior", "HIGH", 1, 4, 300, "Detects internal hosts connecting to public addresses on uncommon ports or with fixed heartbeat intervals."),
    ("LATERAL_MOVEMENT", "Lateral movement", "behavior", "CRITICAL", 1, 5, 60, "Detects internal movement across SMB, RDP, SSH and Windows administrative shares."),
    ("HOST_SCAN", "Host scan", "scan", "HIGH", 1, 30, 10, "Detects one source host contacting many different destination hosts in a short time window."),
    ("TLS_FINGERPRINT", "TLS fingerprint risk", "tls", "HIGH", 1, 1, 0, "Detects weak TLS versions, weak ciphers and suspicious certificate indicators in TLS metadata."),
    ("ML_ANOMALY", "ML anomaly score", "behavior", "MEDIUM", 1, 80, 0, "Uses a lightweight anomaly score based on packet size, protocol and port features."),
    ("WEB_ATTACK", "Web attack detection (advanced)", "web", "HIGH", 1, 1, 0, "Detects XXE, SSTI, CRLF injection, LDAP/XPath injection, deserialization, webshell, buffer overflow and sensitive file discovery."),
]
