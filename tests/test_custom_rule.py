from __future__ import annotations

from detection.engine import DetectionEngine
from models import CustomRuleRecord, PacketRecord
from storage.database import Database
from storage.repositories import CustomRuleRepository


def test_custom_rule_matches_packet_fields():
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=8080,
        protocol="HTTP",
        http_path="/admin",
        raw_summary="GET /admin HTTP/1.1",
    )
    engine = DetectionEngine.from_rule_records(
        [],
        [
            CustomRuleRecord(
                id=1,
                name="Admin path",
                severity="MEDIUM",
                enabled=True,
                protocol="HTTP",
                dst_port=8080,
                keyword="/admin",
                description="检测管理路径访问",
            )
        ],
        alert_cooldown_seconds=0,
    )

    alerts = engine.process_packet(packet)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "CUSTOM_1"
    assert alerts[0].alert_type == "CUSTOM_RULE"


def test_custom_rule_repository_crud(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = CustomRuleRepository(database)

    rule_id = repository.add(CustomRuleRecord(name="DNS keyword", protocol="DNS", keyword="example.com"))
    rules = repository.list_all()

    assert len(rules) == 1
    assert rules[0].id == rule_id
    assert rules[0].protocol == "DNS"

    repository.delete(rule_id)
    assert repository.list_all() == []
