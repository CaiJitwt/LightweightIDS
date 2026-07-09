from __future__ import annotations

from detection.baseline import BaselineManager
from detection.engine import DetectionEngine
from detection.rules.bandwidth_spike import BandwidthSpikeRule
from detection.rules.baseline_deviation import BaselineDeviationRule
from detection.rules.session_duration_anomaly import SessionDurationAnomalyRule
from models import BaselineRecord, PacketRecord, RuleRecord
from storage.database import Database
from storage.repositories import BaselineRepository, RuleRepository


def packet(
    *,
    second: int,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "8.8.8.8",
    dst_port: int = 80,
    protocol: str = "TCP",
    length: int = 100,
) -> PacketRecord:
    minute, sec = divmod(second, 60)
    return PacketRecord(
        timestamp=f"2026-01-01 00:{minute:02d}:{sec:02d}.000",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
    )


def test_baseline_manager_tracks_sliding_source_statistics():
    manager = BaselineManager(window_seconds=60)
    manager.update(packet(second=0, dst_ip="8.8.8.8", dst_port=80, length=100))
    record = manager.update(packet(second=1, dst_ip="1.1.1.1", dst_port=443, length=300))

    assert record is not None
    assert record.packet_count == 2
    assert record.connection_count == 2
    assert record.unique_dst_ips == 2
    assert record.unique_dst_ports == 2
    assert record.avg_packet_length == 200
    assert record.bytes_per_window == 400
    assert record.internal_to_external_ratio == 1.0


def test_baseline_deviation_rule_alerts_after_normal_baseline_then_spike():
    rule = BaselineDeviationRule(threshold=2, time_window=60, min_history=5)
    alerts = []

    for second in range(6):
        alerts.extend(rule.process(packet(second=second, dst_ip="8.8.8.8", dst_port=80, length=100)))

    assert alerts == []

    for index in range(8):
        alerts.extend(
            rule.process(
                packet(
                    second=10 + index,
                    dst_ip=f"93.184.216.{index + 1}",
                    dst_port=8000 + index,
                    length=1200,
                )
            )
        )

    assert any(alert.alert_type == "BASELINE_DEVIATION" for alert in alerts)


def test_bandwidth_spike_rule_alerts_on_byte_volume_spike():
    rule = BandwidthSpikeRule(threshold=3, time_window=60, min_history=5, min_extra_bytes=2000)
    alerts = []

    for second in range(6):
        alerts.extend(rule.process(packet(second=second, length=200)))

    assert alerts == []

    for second in range(10, 14):
        alerts.extend(rule.process(packet(second=second, length=3000)))

    assert any(alert.alert_type == "BANDWIDTH_SPIKE" for alert in alerts)


def test_session_duration_anomaly_rule_uses_approximate_flow_duration():
    rule = SessionDurationAnomalyRule(threshold=2, time_window=600, min_history=4, min_extra_seconds=10)
    alerts = []

    for index in range(4):
        first_seen = index * 20
        dst_port = 8000 + index
        alerts.extend(rule.process(packet(second=first_seen, dst_port=dst_port)))
        alerts.extend(rule.process(packet(second=first_seen + 5, dst_port=dst_port)))

    assert alerts == []

    alerts.extend(rule.process(packet(second=120, dst_port=9000)))
    alerts.extend(rule.process(packet(second=170, dst_port=9000)))

    assert any(alert.alert_type == "SESSION_DURATION_ANOMALY" for alert in alerts)


def test_baseline_repository_persists_summary(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = BaselineRepository(database)
    repository.upsert(
        BaselineRecord(
            src_ip="192.168.1.10",
            updated_at="2026-01-01 00:00:00.000",
            window_seconds=60,
            packet_count=5,
            connection_count=2,
            unique_dst_ips=2,
            unique_dst_ports=2,
            avg_packet_length=128.0,
            bytes_per_window=640,
            internal_to_external_ratio=0.5,
        )
    )

    records = repository.list_all()

    assert len(records) == 1
    assert records[0].src_ip == "192.168.1.10"
    assert records[0].bytes_per_window == 640


def test_database_initializes_baseline_rules_and_table(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()

    rule_ids = {rule.id for rule in RuleRepository(database).list_all()}
    assert {"BASELINE_DEVIATION", "BANDWIDTH_SPIKE", "SESSION_DURATION_ANOMALY"} <= rule_ids

    with database.connect() as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'baselines'"
        ).fetchone()

    assert table is not None


def test_detection_engine_registers_baseline_rules_from_rule_records():
    engine = DetectionEngine.from_rule_records(
        [
            RuleRecord("BASELINE_DEVIATION", "Baseline deviation", "behavior", "HIGH", True, 2, 60, ""),
            RuleRecord("BANDWIDTH_SPIKE", "Bandwidth spike", "behavior", "HIGH", True, 3, 60, ""),
            RuleRecord("SESSION_DURATION_ANOMALY", "Session duration anomaly", "behavior", "MEDIUM", True, 2, 600, ""),
        ],
        alert_cooldown_seconds=0,
    )

    rule_ids = {rule.rule_id for rule in engine.rules}

    assert {"BASELINE_DEVIATION", "BANDWIDTH_SPIKE", "SESSION_DURATION_ANOMALY"} <= rule_ids
