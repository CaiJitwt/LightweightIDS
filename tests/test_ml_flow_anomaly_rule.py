from __future__ import annotations

from detection.engine import DetectionEngine
from detection.features import FlowFeature
from detection.ml import IsolationForestFlowDetector
from detection.rules.ml_flow_anomaly import MlFlowAnomalyRule
from models import PacketRecord, RuleRecord


def packet(
    *,
    second: int,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    dst_port: int = 80,
    length: int = 100,
    tcp_flags: str | None = None,
) -> PacketRecord:
    minute, sec = divmod(second, 60)
    return PacketRecord(
        timestamp=f"2026-01-01 00:{minute:02d}:{sec:02d}.000",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        length=length,
        tcp_flags=tcp_flags,
    )


def test_isolation_forest_detector_falls_back_without_sklearn_and_scores_flow_spike(tmp_path):
    detector = IsolationForestFlowDetector(
        model_path=tmp_path / "flow_anomaly.pkl",
        use_sklearn=False,
        min_train_samples=3,
    )
    normal = [
        FlowFeature("192.168.1.10", "192.168.1.20", 0, 60, packet_count=2, byte_count=200, unique_dst_ports=1),
        FlowFeature("192.168.1.10", "192.168.1.20", 60, 60, packet_count=2, byte_count=220, unique_dst_ports=1),
        FlowFeature("192.168.1.10", "192.168.1.20", 120, 60, packet_count=3, byte_count=260, unique_dst_ports=1),
    ]
    detector.train(normal)

    result = detector.score_feature(
        FlowFeature(
            "192.168.1.10",
            "192.168.1.20",
            180,
            60,
            packet_count=25,
            byte_count=25000,
            unique_dst_ports=12,
            unique_dst_ips=1,
            syn_count=25,
            sensitive_port_count=4,
        )
    )

    assert result.backend == "simple_fallback"
    assert result.score >= 80
    assert result.reasons


def test_flow_detector_save_and_load_round_trip(tmp_path):
    model_path = tmp_path / "flow_anomaly.pkl"
    detector = IsolationForestFlowDetector(model_path=model_path, use_sklearn=False, min_train_samples=1)
    detector.train([FlowFeature("10.0.0.1", "10.0.0.2", 0, 60, packet_count=1, byte_count=100)])
    detector.save()

    loaded = IsolationForestFlowDetector(model_path=model_path, use_sklearn=False)

    assert loaded.load() is True
    assert len(loaded._history) == 1


def test_ml_flow_anomaly_rule_alerts_after_normal_baseline_then_spike(tmp_path):
    detector = IsolationForestFlowDetector(
        model_path=tmp_path / "flow_anomaly.pkl",
        use_sklearn=False,
        min_train_samples=5,
    )
    rule = MlFlowAnomalyRule(detector=detector, threshold=80, time_window=60)
    alerts = []

    for second in range(5):
        alerts.extend(rule.process(packet(second=second, dst_port=80, length=100)))

    assert alerts == []

    for index in range(12):
        alerts.extend(
            rule.process(
                packet(
                    second=10 + index,
                    dst_port=8000 + index,
                    length=2000,
                    tcp_flags="S",
                )
            )
        )

    assert any(alert.rule_id == "ML_FLOW_ANOMALY" for alert in alerts)
    assert any(alert.alert_type == "ML_ANOMALY" for alert in alerts)
    assert any("score=" in alert.evidence and "top_reasons=" in alert.evidence for alert in alerts)


def test_detection_engine_registers_ml_flow_rule_from_records():
    engine = DetectionEngine.from_rule_records(
        [RuleRecord("ML_FLOW_ANOMALY", "ML flow anomaly", "behavior", "HIGH", True, 80, 60, "")],
        alert_cooldown_seconds=0,
    )

    assert "ML_FLOW_ANOMALY" in {rule.rule_id for rule in engine.rules}
