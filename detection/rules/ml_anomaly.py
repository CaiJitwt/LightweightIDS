from __future__ import annotations

from detection.ml.simple_anomaly import SimpleAnomalyDetector
from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class MlAnomalyRule(RuleBase):
    rule_id = "ML_ANOMALY"
    name = "ML anomaly score"
    category = "behavior"
    severity = "MEDIUM"
    threshold = 80
    time_window = 0

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.detector = SimpleAnomalyDetector()

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        result = self.detector.score_packet(packet)
        if result.score < self.threshold:
            return []

        severity = "HIGH" if result.score >= 90 else self.severity
        return [
            self.create_alert(
                packet,
                alert_type="ML_ANOMALY",
                severity=severity,
                description="Simple anomaly model assigned a high risk score to this packet.",
                evidence=f"score={result.score:.1f}; reasons={result.reasons}",
            )
        ]

    def reset(self) -> None:
        self.detector.reset()
