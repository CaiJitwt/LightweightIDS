from __future__ import annotations

from detection.engine import DetectionEngine
from detection.rules.signature_rule import SignatureRule
from detection.signature_matcher import Signature, SignatureMatcher
from models import PacketRecord, RuleRecord
from storage.database import Database
from storage.repositories import RuleRepository


def packet(raw_summary: str = "", http_path: str | None = None) -> PacketRecord:
    return PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="HTTP",
        http_host="example.test",
        http_path=http_path,
        raw_summary=raw_summary,
    )


def test_signature_rule_converts_signature_match_to_alert():
    matcher = SignatureMatcher(
        [
            Signature(
                id="SIG_TEST_WEBSHELL",
                name="Webshell indicator",
                category="webshell_indicator",
                severity="CRITICAL",
                match_type="keyword",
                pattern="webshell",
                description="Detected a webshell indicator.",
            )
        ]
    )
    rule = SignatureRule(matcher=matcher)

    alerts = rule.process(packet(raw_summary="HTTP request user-agent=webshell monitor"))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SIGNATURE_MATCH"
    assert alerts[0].rule_name == "External signature match"
    assert alerts[0].alert_type == "WEBSHELL_INDICATOR"
    assert alerts[0].severity == "CRITICAL"
    assert "SIG_TEST_WEBSHELL" in alerts[0].evidence


def test_signature_rule_respects_rule_record_severity_override():
    record = RuleRecord(
        id="SIGNATURE_MATCH",
        name="External signature match",
        category="signature",
        severity="MEDIUM",
        enabled=True,
        threshold=1,
        time_window=0,
        description="Detects packets matching signatures.",
    )
    engine = DetectionEngine.from_rule_records([record], alert_cooldown_seconds=0)

    alerts = engine.process_packet(packet(http_path="/?q=<script>alert(1)</script>"))

    assert len(alerts) >= 1
    assert alerts[0].rule_id == "SIGNATURE_MATCH"
    assert alerts[0].severity == "MEDIUM"


def test_detection_engine_registers_signature_rule():
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)
    rule_ids = {rule.rule_id for rule in engine.rules}

    assert "SIGNATURE_MATCH" in rule_ids


def test_database_initializes_signature_rule(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()

    rules = {rule.id for rule in RuleRepository(database).list_all()}

    assert "SIGNATURE_MATCH" in rules
