from __future__ import annotations

from detection.rules.blacklist import BlacklistRule
from detection.rules.icmp_flood import IcmpFloodRule
from detection.rules.sensitive_port import SensitivePortRule
from models import PacketRecord


def test_icmp_flood_rule_triggers_at_threshold():
    rule = IcmpFloodRule(threshold=2, time_window=10)
    first = PacketRecord(timestamp="2026-01-01 00:00:00.000", src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="ICMP")
    second = PacketRecord(timestamp="2026-01-01 00:00:01.000", src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="ICMP")

    assert rule.process(first) == []
    alerts = rule.process(second)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "ICMP_FLOOD"


def test_sensitive_port_rule_triggers_on_default_sensitive_port():
    rule = SensitivePortRule()
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=3389,
        protocol="TCP",
    )

    alerts = rule.process(packet)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SENSITIVE_PORT"
    assert "RDP" in alerts[0].evidence


def test_blacklist_rule_triggers_on_src_or_dst_match():
    rule = BlacklistRule(blacklist={"203.0.113.9"})
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="203.0.113.9",
        dst_ip="10.0.0.2",
        protocol="TCP",
    )

    alerts = rule.process(packet)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "BLACKLIST_IP"
    assert "203.0.113.9" in alerts[0].evidence
