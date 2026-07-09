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
    ("PORT_SCAN", "端口扫描检测", "scan", "HIGH", 1, 20, 10, "检测同一源 IP 在短时间内访问同一目标的多个端口。"),
    ("SYN_FLOOD", "SYN Flood 检测", "flood", "HIGH", 1, 100, 10, "检测短时间内大量 TCP SYN 请求。"),
    ("ICMP_FLOOD", "ICMP Flood 检测", "flood", "MEDIUM", 1, 50, 10, "检测短时间内大量 ICMP 数据包。"),
    ("SENSITIVE_PORT", "敏感端口访问检测", "policy", "MEDIUM", 1, 1, 0, "检测对常见敏感服务端口的访问。"),
    ("BLACKLIST_IP", "黑名单 IP 检测", "reputation", "HIGH", 1, 1, 0, "检测源 IP 或目标 IP 是否命中本地黑名单。"),
    ("SQL_INJECTION", "SQL 注入检测", "injection", "CRITICAL", 1, 1, 0, "检测 HTTP 请求中的 SQL 注入攻击特征。"),
    ("XSS", "XSS 攻击检测", "injection", "HIGH", 1, 1, 0, "检测 HTTP 请求中的 XSS 跨站脚本攻击特征。"),
    ("WEB_ATTACK", "Web 攻击检测", "web", "HIGH", 1, 1, 0, "检测目录遍历、命令注入、SSRF、文件包含、反序列化等 Web 攻击。"),
]
