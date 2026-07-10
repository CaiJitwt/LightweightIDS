from __future__ import annotations

from detection.analysis.attack_chain import AttackChainAnalyzer
from detection.analysis.host_risk import HostRiskScorer
from models import AlertRecord, BaselineRecord


def alert(
    rule_id: str,
    severity: str,
    src_ip: str,
    dst_ip: str = "10.0.1.10",
    timestamp: str = "2026-01-01 00:00:00.000",
    alert_type: str | None = None,
) -> AlertRecord:
    return AlertRecord(
        timestamp=timestamp,
        rule_id=rule_id,
        rule_name=rule_id,
        alert_type=alert_type or rule_id,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description="test",
        evidence="test",
    )


def test_host_risk_scorer_ranks_severity_chain_and_baseline_top_host():
    alerts = [
        alert("HOST_SCAN", "HIGH", "10.0.0.10", timestamp="2026-01-01 00:00:00.000"),
        alert("SQL_INJECTION", "CRITICAL", "10.0.0.10", timestamp="2026-01-01 00:00:01.000"),
        alert("MALICIOUS_COMMAND", "CRITICAL", "10.0.0.10", timestamp="2026-01-01 00:00:02.000"),
        alert("TLS_FINGERPRINT", "HIGH", "10.0.0.10", timestamp="2026-01-01 00:00:03.000"),
        alert(
            "LATERAL_MOVEMENT",
            "CRITICAL",
            "10.0.0.10",
            timestamp="2026-01-01 00:00:04.000",
            alert_type="ADMIN_SHARE_ACCESS",
        ),
        alert("SENSITIVE_PORT", "MEDIUM", "10.0.0.20", dst_ip="10.0.1.20"),
    ]
    baselines = [
        BaselineRecord(src_ip="10.0.0.10", packet_count=100, connection_count=40, unique_dst_ips=30, unique_dst_ports=8, bytes_per_window=50_000),
        BaselineRecord(src_ip="10.0.0.20", packet_count=10, connection_count=4, unique_dst_ips=2, unique_dst_ports=1, bytes_per_window=1_000),
    ]
    chains = AttackChainAnalyzer().analyze(alerts)

    risks = HostRiskScorer().score_hosts(alerts, chains, baselines, asset_importance={"10.0.0.10": 90})

    assert risks[0].source_ip == "10.0.0.10"
    assert risks[0].score > risks[1].score
    assert risks[0].chain_score > 0
    assert risks[0].baseline_score == 100
