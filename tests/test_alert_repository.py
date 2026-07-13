from __future__ import annotations

from models import AlertRecord
from models import RuleRecord
from storage.database import Database
from storage.repositories import AlertRepository, RuleRepository


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

    assert repository.delete(updated[0].id) is True  # type: ignore[arg-type]
    assert repository.list_all(severity="HIGH") == []
    assert repository.delete(999_999) is False


def test_alert_repository_time_buckets_and_rule_feedback(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = AlertRepository(database)
    repository.add_many(
        [
            AlertRecord(timestamp="2026-01-01 00:10:00.000", rule_id="SQL_INJECTION", rule_name="SQL injection", alert_type="SQL_INJECTION", severity="CRITICAL", status="confirmed"),
            AlertRecord(timestamp="2026-01-01 00:20:00.000", rule_id="SQL_INJECTION", rule_name="SQL injection", alert_type="SQL_INJECTION", severity="CRITICAL", status="ignored"),
            AlertRecord(timestamp="2026-01-01 01:05:00.000", rule_id="XSS", rule_name="XSS", alert_type="XSS", severity="HIGH", status="unconfirmed"),
        ]
    )

    assert repository.count_by_time_bucket(bucket="hour", limit=24) == [
        ("2026-01-01 00:00", 2),
        ("2026-01-01 01:00", 1),
    ]

    feedback = repository.rule_feedback()
    assert feedback["SQL_INJECTION"]["total"] == 2
    assert feedback["SQL_INJECTION"]["confirmed"] == 1
    assert feedback["SQL_INJECTION"]["ignored"] == 1
    assert feedback["SQL_INJECTION"]["confirmed_ratio"] == 0.5
    assert feedback["XSS"]["unconfirmed"] == 1


def test_rule_repository_update_still_preserves_editable_fields(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = RuleRepository(database)
    original = next(rule for rule in repository.list_all() if rule.id == "HOST_SCAN")

    repository.update_rule(
        RuleRecord(
            id=original.id,
            name=original.name,
            category=original.category,
            severity=original.severity,
            enabled=False,
            threshold=42,
            time_window=15,
            description="Updated host scan description",
        )
    )

    updated = next(rule for rule in repository.list_all() if rule.id == "HOST_SCAN")
    assert updated.enabled is False
    assert updated.threshold == 42
    assert updated.time_window == 15
    assert updated.description == "Updated host scan description"
