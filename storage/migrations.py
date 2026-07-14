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

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL UNIQUE,
    updated_at TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    connection_count INTEGER NOT NULL DEFAULT 0,
    unique_dst_ips INTEGER NOT NULL DEFAULT 0,
    unique_dst_ports INTEGER NOT NULL DEFAULT 0,
    avg_packet_length REAL NOT NULL DEFAULT 0,
    bytes_per_window INTEGER NOT NULL DEFAULT 0,
    internal_to_external_ratio REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    ip TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'Other',
    importance INTEGER NOT NULL DEFAULT 50 CHECK (importance BETWEEN 0 AND 100),
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    priority TEXT NOT NULL DEFAULT 'MEDIUM',
    host_ip TEXT,
    summary TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigation_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER NOT NULL,
    alert_id INTEGER,
    alert_timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
    UNIQUE (investigation_id, alert_id)
);

CREATE TABLE IF NOT EXISTS blocklist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    field TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'ANY',
    enabled INTEGER NOT NULL DEFAULT 1,
    enforcement_status TEXT NOT NULL DEFAULT 'Pending',
    enforcement_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (kind, value, field, protocol)
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    channel TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    record_id INTEGER NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    computer TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT '',
    user TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    logon_type TEXT NOT NULL DEFAULT '',
    process_name TEXT NOT NULL DEFAULT '',
    command_line TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    severity TEXT NOT NULL DEFAULT 'INFO',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (channel, record_id)
);

CREATE TABLE IF NOT EXISTS security_event_cursors (
    channel TEXT PRIMARY KEY,
    last_record_id INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_event_alert_links (
    security_event_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (security_event_id, alert_id),
    FOREIGN KEY (security_event_id) REFERENCES security_events(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packets_alert_match
ON packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol);

CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets (protocol);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets (src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets (dst_port);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_status ON alerts (rule_id, status);
CREATE INDEX IF NOT EXISTS idx_packets_src_timestamp ON packets (src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_dst_timestamp ON packets (dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_timestamp ON alerts (src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_timestamp ON alerts (dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations (status, updated_at);
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_case ON investigation_evidence (investigation_id, added_at);
CREATE INDEX IF NOT EXISTS idx_blocklist_enabled ON blocklist_entries (enabled, kind, field);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_event_id ON security_events (event_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_source ON security_events (source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_event_links_event ON security_event_alert_links (security_event_id);
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
    ("LATERAL_MOVEMENT", "Lateral movement", "behavior", "CRITICAL", 1, 5, 60, "Detects internal movement across SMB, RPC, RDP, SSH, WinRM and Windows administrative shares."),
    ("HOST_SCAN", "Host scan", "scan", "HIGH", 1, 30, 10, "Detects one source host contacting many different destination hosts in a short time window."),
    ("TLS_FINGERPRINT", "TLS fingerprint risk", "tls", "HIGH", 1, 1, 0, "Detects weak TLS versions, weak ciphers and suspicious certificate indicators in TLS metadata."),
    ("ML_ANOMALY", "ML anomaly score", "behavior", "MEDIUM", 1, 80, 0, "Uses a lightweight anomaly score based on packet size, protocol and port features."),
    ("WEB_ATTACK", "Web attack detection (advanced)", "web", "HIGH", 1, 1, 0, "Detects traversal, command injection, SSRF, file inclusion, XXE, SSTI, deserialization, webshell and sensitive file discovery."),
    ("ML_FLOW_ANOMALY", "ML flow anomaly", "behavior", "HIGH", 1, 80, 60, "Uses flow-level features with IsolationForest or a lightweight fallback model to detect anomalous host behavior."),
    ("SIGNATURE_MATCH", "External signature match", "signature", "HIGH", 1, 1, 0, "Detects packets matching the external defensive signature library."),
    ("BASELINE_DEVIATION", "Baseline deviation", "behavior", "HIGH", 1, 3, 60, "Detects hosts whose activity exceeds historical packet, destination, port or byte baselines."),
    ("BANDWIDTH_SPIKE", "Bandwidth spike", "behavior", "HIGH", 1, 4, 60, "Detects hosts whose byte volume sharply exceeds their historical baseline."),
    ("SESSION_DURATION_ANOMALY", "Session duration anomaly", "behavior", "MEDIUM", 1, 3, 600, "Detects sessions that last much longer than the host historical average."),
    ("WINDOWS_LOGON_FAILURE", "Windows logon failure burst", "host", "HIGH", 1, 5, 120, "Detects repeated Windows authentication failures from the same source or account."),
    ("WINDOWS_PERSISTENCE", "Windows persistence change", "host", "HIGH", 1, 1, 0, "Detects service and scheduled-task creation or modification events."),
    ("WINDOWS_PRIVILEGE_CHANGE", "Windows privilege change", "host", "HIGH", 1, 1, 0, "Detects account creation and privileged group membership changes."),
    ("POWERSHELL_SUSPICIOUS", "Suspicious PowerShell activity", "host", "HIGH", 1, 3, 0, "Detects suspicious indicators in PowerShell operational events."),
    ("SECURITY_CONTROL_TAMPER", "Security control tampering", "host", "CRITICAL", 1, 1, 0, "Detects security-log clearing and protection-disable events."),
    ("RDP_LATERAL_ACTIVITY", "RDP lateral activity", "host", "HIGH", 1, 3, 300, "Detects repeated remote interactive logons from the same source."),
]
