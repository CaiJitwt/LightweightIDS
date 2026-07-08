from __future__ import annotations

from detection.analysis.attack_chain import AttackChainAnalyzer
from detection.analysis.false_positive import AlertNoiseReducer
from detection.engine import DetectionEngine
from detection.rules.ml_anomaly import MlAnomalyRule
from detection.rules.tls_fingerprint import TlsFingerprintRule
from models import AlertRecord, PacketRecord


def alert(
    *,
    timestamp: str,
    rule_id: str,
    alert_type: str,
    src_ip: str = "192.168.1.10",
    severity: str = "HIGH",
) -> AlertRecord:
    return AlertRecord(
        timestamp=timestamp,
        rule_id=rule_id,
        rule_name=rule_id,
        alert_type=alert_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip="192.168.1.20",
        description="test",
        evidence="test",
    )


def test_tls_fingerprint_rule_detects_weak_version_and_cipher():
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        dst_port=443,
        protocol="TLS",
        raw_summary="TLS ClientHello version=TLSv1.0 cipher=RC4",
    )

    alerts = TlsFingerprintRule().process(packet)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "TLS_WEAK_FINGERPRINT"


def test_ml_anomaly_rule_detects_high_risk_packet_features():
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        dst_port=31337,
        protocol="UNKNOWN",
        length=10000,
    )

    alerts = MlAnomalyRule(threshold=80).process(packet)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "ML_ANOMALY"
    assert "score=" in alerts[0].evidence


def test_attack_chain_analyzer_links_stages_by_source_ip():
    alerts = [
        alert(timestamp="2026-01-01 00:00:00.000", rule_id="HOST_SCAN", alert_type="HOST_SCAN"),
        alert(timestamp="2026-01-01 00:00:10.000", rule_id="SQL_INJECTION", alert_type="SQL_INJECTION"),
        alert(timestamp="2026-01-01 00:00:20.000", rule_id="MALICIOUS_COMMAND", alert_type="MALICIOUS_COMMAND", severity="CRITICAL"),
    ]

    chains = AttackChainAnalyzer().analyze(alerts)

    assert len(chains) == 1
    assert chains[0].source_ip == "192.168.1.10"
    assert chains[0].stages == ["scan", "exploit", "execution"]
    assert chains[0].risk_score > 50


def test_noise_reducer_filters_whitelist_and_merges_duplicates():
    reducer = AlertNoiseReducer(whitelist_ips={"192.168.1.10"}, merge_window_seconds=60)
    alerts = [
        alert(timestamp="2026-01-01 00:00:00.000", rule_id="HOST_SCAN", alert_type="HOST_SCAN"),
        alert(timestamp="2026-01-01 00:00:10.000", rule_id="HOST_SCAN", alert_type="HOST_SCAN", src_ip="192.168.1.11"),
        alert(timestamp="2026-01-01 00:00:20.000", rule_id="HOST_SCAN", alert_type="HOST_SCAN", src_ip="192.168.1.11"),
    ]

    filtered = reducer.filter_alerts(alerts)

    assert len(filtered) == 1
    assert filtered[0].src_ip == "192.168.1.11"


def test_noise_reducer_raises_severity_for_important_asset():
    reducer = AlertNoiseReducer(asset_importance={"192.168.1.20": 95})
    adjusted = reducer.apply_asset_importance(
        alert(
            timestamp="2026-01-01 00:00:00.000",
            rule_id="DNS_ANOMALY",
            alert_type="DNS_QUERY_FREQUENCY",
            severity="MEDIUM",
        )
    )

    assert adjusted.severity == "HIGH"
    assert "asset_importance=95" in adjusted.evidence


def test_detection_engine_registers_phase_three_rules():
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)
    rule_ids = {rule.rule_id for rule in engine.rules}

    assert {"TLS_FINGERPRINT", "ML_ANOMALY"} <= rule_ids
