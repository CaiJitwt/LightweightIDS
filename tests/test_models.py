from __future__ import annotations

import pytest

from models import AlertRecord, PacketRecord, RuleRecord


def test_packet_record_defaults():
    packet = PacketRecord(timestamp="2026-01-01T00:00:00", protocol="TCP", length=60)
    assert packet.protocol == "TCP"
    assert packet.length == 60


def test_alert_record_validates_severity():
    with pytest.raises(ValueError):
        AlertRecord(severity="INVALID")


def test_rule_record_fields():
    rule = RuleRecord(
        id="TEST",
        name="测试规则",
        category="test",
        severity="LOW",
        enabled=True,
        threshold=1,
        time_window=10,
        description="用于测试",
    )
    assert rule.enabled is True
