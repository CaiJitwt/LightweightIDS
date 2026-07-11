from __future__ import annotations

import pytest

from detection.analysis.host_profile import HostProfileService
from detection.engine import DetectionEngine
from models import AlertRecord, AssetRecord, InvestigationRecord, PacketRecord, RuleRecord
from report.report_generator import ReportGenerator
from storage.analyst_repositories import AssetRepository, InvestigationRepository
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository


def test_analyst_schema_is_additive_and_idempotent(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    database.initialize()

    with database.connect() as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }

    assert {"assets", "investigations", "investigation_evidence"} <= tables
    assert {"idx_packets_src_timestamp", "idx_alerts_dst_timestamp", "idx_investigation_evidence_case"} <= indexes


def test_asset_repository_validates_crud_and_importance_map(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = AssetRepository(database)
    repository.save(AssetRecord(ip="10.0.0.10", display_name="Database A", role="Database", importance=90))

    asset = repository.get("10.0.0.10")
    assert asset is not None
    assert asset.display_name == "Database A"
    assert repository.importance_map() == {"10.0.0.10": 90}

    repository.save(AssetRecord(ip="10.0.0.10", display_name="Database B", role="Server", importance=80))
    assert repository.get("10.0.0.10").display_name == "Database B"  # type: ignore[union-attr]
    assert repository.delete("10.0.0.10") is True
    assert repository.get("10.0.0.10") is None

    with pytest.raises(ValueError):
        AssetRecord(ip="not-an-ip")
    with pytest.raises(ValueError):
        AssetRecord(ip="10.0.0.1", importance=101)


def test_host_profile_aggregates_both_directions_and_asset_risk(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    AssetRepository(database).save(
        AssetRecord(ip="10.0.0.1", display_name="Admin host", role="Workstation", importance=95)
    )
    PacketRepository(database).add_many(
        [
            PacketRecord(timestamp="2026-07-11 10:00:00.000", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=443, protocol="HTTPS", length=120, raw_summary="TLS metadata"),
            PacketRecord(timestamp="2026-07-11 10:00:01.000", src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=443, dst_port=50000, protocol="HTTPS", length=140, raw_summary="TLS metadata response"),
        ]
    )
    AlertRepository(database).add(
        AlertRecord(
            timestamp="2026-07-11 10:00:00.000",
            rule_id="TLS_FINGERPRINT",
            rule_name="TLS fingerprint risk",
            alert_type="TLS_WEAK_FINGERPRINT",
            severity="HIGH",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=50000,
            dst_port=443,
            protocol="HTTPS",
            description="Suspicious TLS metadata fingerprint.",
            evidence="weak_version=true",
        )
    )

    service = HostProfileService(database)
    hosts = {host.ip: host for host in service.list_hosts()}
    assert hosts["10.0.0.1"].display_name == "Admin host"
    assert hosts["10.0.0.1"].packet_count == 2
    assert hosts["10.0.0.1"].incoming_packets == 1
    assert hosts["10.0.0.1"].outgoing_packets == 1
    assert hosts["10.0.0.1"].risk_score > 0
    assert service.connections("10.0.0.1")
    assert service.alerts_for_host("10.0.0.2")
    assert {event.event_type for event in service.timeline("10.0.0.1")} == {"Packet", "Alert"}


def test_asset_importance_can_raise_alert_severity_without_changing_defaults():
    record = RuleRecord(
        id="SENSITIVE_PORT",
        name="Sensitive port access",
        category="policy",
        severity="MEDIUM",
        enabled=True,
        threshold=1,
        time_window=0,
        description="Sensitive port access",
    )
    packet = PacketRecord(
        timestamp="2026-07-11 10:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=22,
        protocol="TCP",
        length=60,
    )

    default_alert = DetectionEngine.from_rule_records([record], alert_cooldown_seconds=0).process_packet(packet)[0]
    important_alert = DetectionEngine.from_rule_records(
        [record],
        alert_cooldown_seconds=0,
        asset_importance={"10.0.0.2": 90},
    ).process_packet(packet)[0]
    assert default_alert.severity == "MEDIUM"
    assert important_alert.severity == "HIGH"


def test_investigation_evidence_survives_alert_deletion_and_exports(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    alerts = AlertRepository(database)
    investigations = InvestigationRepository(database)
    alert = AlertRecord(
        timestamp="2026-07-11 10:00:00.000",
        rule_id="SQL_INJECTION",
        rule_name="SQL injection detection",
        alert_type="SQL_INJECTION",
        severity="CRITICAL",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        description="SQL injection indicator.",
        evidence="union select",
    )
    alert.id = alerts.add(alert)
    investigation_id = investigations.add(
        InvestigationRecord(title="Review SQL injection", priority="CRITICAL", host_ip="10.0.0.1")
    )

    assert investigations.add_evidence(investigation_id, alert) is True
    assert investigations.add_evidence(investigation_id, alert) is False
    assert alerts.delete(alert.id) is True
    evidence = investigations.list_evidence(investigation_id)
    assert len(evidence) == 1
    assert evidence[0].alert_id is None
    assert evidence[0].evidence == "union select"

    report_path = tmp_path / "investigation.html"
    ReportGenerator().generate_investigation_html(investigations.get(investigation_id), evidence, report_path)  # type: ignore[arg-type]
    report = report_path.read_text(encoding="utf-8")
    assert "Review SQL injection" in report
    assert "union select" in report
