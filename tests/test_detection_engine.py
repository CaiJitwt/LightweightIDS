from __future__ import annotations

from detection.engine import DetectionEngine
from detection.rules.sensitive_port import SensitivePortRule
from models import PacketRecord


def packet(timestamp: str = "2026-01-01 00:00:00.000", dst_port: int = 22) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
    )


def test_detection_engine_with_no_rules_returns_no_alerts():
    engine = DetectionEngine()
    alerts = engine.process_packet(PacketRecord(protocol="TCP"))
    assert alerts == []


def test_detection_engine_calls_enabled_rules():
    engine = DetectionEngine(rules=[SensitivePortRule()], alert_cooldown_seconds=0)

    alerts = engine.process_packet(packet())

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SENSITIVE_PORT"


def test_detection_engine_can_disable_rule():
    engine = DetectionEngine(rules=[SensitivePortRule()], alert_cooldown_seconds=0)
    engine.set_rule_enabled("SENSITIVE_PORT", False)

    alerts = engine.process_packet(packet())

    assert alerts == []


def test_detection_engine_applies_alert_cooldown():
    engine = DetectionEngine(rules=[SensitivePortRule()], alert_cooldown_seconds=10)

    first = engine.process_packet(packet("2026-01-01 00:00:00.000"))
    second = engine.process_packet(packet("2026-01-01 00:00:05.000"))
    third = engine.process_packet(packet("2026-01-01 00:00:11.000"))

    assert len(first) == 1
    assert second == []
    assert len(third) == 1
