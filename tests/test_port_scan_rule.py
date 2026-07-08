from __future__ import annotations

from detection.rules.port_scan import PortScanRule
from models import PacketRecord


def make_packet(dst_port: int, second: int) -> PacketRecord:
    return PacketRecord(
        timestamp=f"2026-01-01 00:00:{second:02d}.000",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=40000 + dst_port,
        dst_port=dst_port,
        protocol="TCP",
    )


def test_port_scan_rule_triggers_on_many_distinct_ports():
    rule = PortScanRule(threshold=3, time_window=10)

    assert rule.process(make_packet(80, 0)) == []
    assert rule.process(make_packet(443, 1)) == []
    alerts = rule.process(make_packet(22, 2))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "PORT_SCAN"
    assert "distinct_ports=3" in alerts[0].evidence


def test_port_scan_rule_respects_time_window():
    rule = PortScanRule(threshold=3, time_window=3)

    assert rule.process(make_packet(80, 0)) == []
    assert rule.process(make_packet(443, 1)) == []
    assert rule.process(make_packet(22, 5)) == []
