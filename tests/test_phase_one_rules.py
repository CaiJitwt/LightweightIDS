from __future__ import annotations

from detection.engine import DetectionEngine
from detection.rules.brute_force import BruteForceRule
from detection.rules.dns_anomaly import DnsAnomalyRule
from detection.rules.http_suspicious import HttpSuspiciousRule
from detection.rules.malicious_command import MaliciousCommandRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.xss import XssRule
from models import PacketRecord


def http_packet(payload: str, path: str = "/") -> PacketRecord:
    return PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="HTTP",
        http_host="example.test",
        http_path=path,
        raw_summary=f"HTTP request | payload={payload}",
    )


def test_sql_injection_rule_detects_union_select():
    alerts = SqlInjectionRule().process(http_packet("GET /search?q=1 UNION SELECT password FROM users HTTP/1.1"))
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"


def test_xss_rule_detects_script_tag():
    alerts = XssRule().process(http_packet("GET /?q=<script>alert(1)</script> HTTP/1.1"))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "XSS"


def test_http_suspicious_rule_detects_traversal():
    alerts = HttpSuspiciousRule().process(http_packet("GET /download?file=../../etc/passwd HTTP/1.1", path="/download"))
    assert len(alerts) == 1
    assert alerts[0].alert_type == "HTTP_SUSPICIOUS"


def test_malicious_command_rule_detects_command_keyword():
    alerts = MaliciousCommandRule().process(http_packet("GET /run?cmd=whoami HTTP/1.1"))
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"


def test_brute_force_rule_triggers_on_repeated_service_connections():
    rule = BruteForceRule(threshold=3, time_window=10)
    packets = [
        PacketRecord(
            timestamp=f"2026-01-01 00:00:0{index}.000",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=50000 + index,
            dst_port=22,
            protocol="TCP",
        )
        for index in range(3)
    ]

    alerts = []
    for packet in packets:
        alerts.extend(rule.process(packet))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "BRUTE_FORCE"


def test_dns_anomaly_rule_detects_long_domain():
    query = "a" * 60 + ".example.com"
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol="DNS",
        dns_query=query,
    )

    alerts = DnsAnomalyRule().process(packet)

    assert any(alert.alert_type == "DNS_TUNNELING_SUSPECTED" for alert in alerts)


def test_detection_engine_registers_phase_one_rules():
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)
    rule_ids = {rule.rule_id for rule in engine.rules}
    assert {"SQL_INJECTION", "XSS", "HTTP_SUSPICIOUS", "MALICIOUS_COMMAND", "BRUTE_FORCE", "DNS_ANOMALY"} <= rule_ids
