from __future__ import annotations

from detection.engine import DetectionEngine
from detection.rules.abnormal_outbound import AbnormalOutboundRule
from detection.rules.host_scan import HostScanRule
from detection.rules.lateral_movement import LateralMovementRule
from models import PacketRecord


def packet(
    *,
    timestamp: str,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    dst_port: int | None = 445,
    protocol: str = "TCP",
    raw_summary: str = "",
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        raw_summary=raw_summary,
    )


def test_host_scan_rule_detects_many_destination_hosts():
    rule = HostScanRule(threshold=3, time_window=10)
    alerts = []

    for index in range(3):
        alerts.extend(
            rule.process(
                packet(
                    timestamp=f"2026-01-01 00:00:0{index}.000",
                    dst_ip=f"192.168.1.{20 + index}",
                    dst_port=80,
                    protocol="TCP",
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "HOST_SCAN"


def test_lateral_movement_rule_detects_many_internal_admin_targets():
    rule = LateralMovementRule(threshold=3, time_window=60)
    alerts = []

    for index in range(3):
        alerts.extend(
            rule.process(
                packet(
                    timestamp=f"2026-01-01 00:00:0{index}.000",
                    dst_ip=f"192.168.1.{30 + index}",
                    dst_port=445,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "LATERAL_MOVEMENT"
    assert alerts[0].severity == "CRITICAL"


def test_lateral_movement_rule_detects_windows_admin_share_access():
    alerts = LateralMovementRule().process(
        packet(
            timestamp="2026-01-01 00:00:00.000",
            raw_summary=r"SMB Tree Connect Request Path: \\192.168.1.20\ADMIN$",
        )
    )

    assert any(alert.alert_type == "ADMIN_SHARE_ACCESS" for alert in alerts)


def test_abnormal_outbound_rule_detects_uncommon_public_port():
    alerts = AbnormalOutboundRule().process(
        packet(
            timestamp="2026-01-01 00:00:00.000",
            dst_ip="8.8.8.8",
            dst_port=4444,
        )
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "NON_STANDARD_OUTBOUND"


def test_abnormal_outbound_rule_detects_fixed_interval_heartbeat():
    rule = AbnormalOutboundRule(threshold=4, time_window=300)
    alerts = []

    for seconds in (0, 10, 20, 30):
        alerts.extend(
            rule.process(
                packet(
                    timestamp=f"2026-01-01 00:00:{seconds:02d}.000",
                    dst_ip="8.8.8.8",
                    dst_port=443,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "C2_HEARTBEAT_SUSPECTED"


def test_detection_engine_registers_phase_two_rules():
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)
    rule_ids = {rule.rule_id for rule in engine.rules}

    assert {"ABNORMAL_OUTBOUND", "LATERAL_MOVEMENT", "HOST_SCAN"} <= rule_ids
