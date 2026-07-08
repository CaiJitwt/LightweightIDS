from __future__ import annotations

from detection.rules.syn_flood import SynFloodRule
from models import PacketRecord


def make_syn(second: int, flags: str = "S") -> PacketRecord:
    return PacketRecord(
        timestamp=f"2026-01-01 00:00:{second:02d}.000",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=50000 + second,
        dst_port=80,
        protocol="TCP",
        tcp_flags=flags,
    )


def test_syn_flood_rule_triggers_on_syn_without_ack():
    rule = SynFloodRule(threshold=3, time_window=10)

    assert rule.process(make_syn(0)) == []
    assert rule.process(make_syn(1)) == []
    alerts = rule.process(make_syn(2))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SYN_FLOOD"
    assert "syn_count=3" in alerts[0].evidence


def test_syn_flood_rule_ignores_syn_ack():
    rule = SynFloodRule(threshold=1, time_window=10)

    alerts = rule.process(make_syn(0, flags="SA"))

    assert alerts == []
