from __future__ import annotations

from models import AlertRecord
from storage.database import Database
from storage.repositories import AlertRepository


def test_alert_repository_saves_lists_filters_and_updates_status(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = AlertRepository(database)

    repository.add_many(
        [
            AlertRecord(
                timestamp="2026-01-01 00:00:00.000",
                rule_id="SENSITIVE_PORT",
                rule_name="敏感端口访问检测",
                alert_type="SENSITIVE_PORT_ACCESS",
                severity="MEDIUM",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                description="访问敏感端口",
                evidence="dst_port=22",
            ),
            AlertRecord(
                timestamp="2026-01-01 00:00:01.000",
                rule_id="BLACKLIST_IP",
                rule_name="黑名单 IP 检测",
                alert_type="BLACKLIST_IP",
                severity="HIGH",
                src_ip="203.0.113.9",
                dst_ip="10.0.0.2",
                description="命中黑名单",
                evidence="matched_ips=['203.0.113.9']",
            ),
        ]
    )

    high_alerts = repository.list_all(severity="HIGH")
    assert len(high_alerts) == 1
    assert high_alerts[0].rule_id == "BLACKLIST_IP"

    keyword_alerts = repository.list_all(keyword="敏感端口")
    assert len(keyword_alerts) == 1

    repository.update_status(high_alerts[0].id, "confirmed")  # type: ignore[arg-type]
    updated = repository.list_all(severity="HIGH")
    assert updated[0].status == "confirmed"
