from __future__ import annotations

from models import AlertRecord, BaselineRecord, PacketRecord
from storage.database import Database
from storage.repositories import BaselineRepository, PacketRepository, SettingsRepository, TrafficRepository


def test_database_enables_wal_busy_timeout_and_runtime_indexes(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()

    with database.connect() as connection:
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        busy_timeout = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
            ).fetchall()
        }

    assert journal_mode == "wal"
    assert busy_timeout == 10_000
    assert {
        "idx_packets_alert_match",
        "idx_alerts_timestamp",
        "idx_alerts_severity",
        "idx_alerts_rule_status",
    } <= indexes


def test_traffic_batch_persists_packets_and_alerts_and_finds_matching_packet(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    traffic_repository = TrafficRepository(database)
    packet_repository = PacketRepository(database)

    packet = PacketRecord(
        timestamp="2026-07-11 22:00:00.000",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=51000,
        dst_port=443,
        protocol="HTTPS",
        length=128,
        raw_summary="TLS metadata packet",
    )
    alert = AlertRecord(
        timestamp=packet.timestamp,
        rule_id="TLS_FINGERPRINT",
        rule_name="TLS fingerprint risk",
        alert_type="TLS_FINGERPRINT",
        severity="HIGH",
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        description="Suspicious TLS metadata fingerprint.",
        evidence="fingerprint=test",
    )

    assert traffic_repository.add_batch([packet], [alert]) == (1, 1)

    matching_packet = packet_repository.find_matching_alert(alert)
    assert matching_packet is not None
    assert matching_packet.id is not None
    assert matching_packet.raw_summary == "TLS metadata packet"


def test_baseline_upsert_many_inserts_and_updates_in_one_batch(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = BaselineRepository(database)

    repository.upsert_many(
        [
            BaselineRecord(src_ip="10.0.0.1", updated_at="2026-07-11 22:00:00", packet_count=10),
            BaselineRecord(src_ip="10.0.0.2", updated_at="2026-07-11 22:00:00", packet_count=20),
        ]
    )
    repository.upsert_many(
        [BaselineRecord(src_ip="10.0.0.1", updated_at="2026-07-11 22:01:00", packet_count=30)]
    )

    records = {record.src_ip: record for record in repository.list_all()}
    assert records["10.0.0.1"].packet_count == 30
    assert records["10.0.0.2"].packet_count == 20


def test_settings_repository_reads_typed_values_and_updates_as_one_batch(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = SettingsRepository(database)

    repository.set_many(
        {
            "auto_save_packets": "false",
            "enable_realtime_detection": "true",
            "alert_cooldown_seconds": "25",
        }
    )

    assert repository.get_bool("auto_save_packets", True) is False
    assert repository.get_bool("enable_realtime_detection", False) is True
    assert repository.get_int("alert_cooldown_seconds", 10) == 25

    repository.set("alert_cooldown_seconds", "not-a-number")
    assert repository.get_int("alert_cooldown_seconds", 10) == 10
