from __future__ import annotations

from detection.features import FlowFeatureExtractor
from detection.ml import DEFAULT_MODEL_PATH, IsolationForestFlowDetector
from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class MlFlowAnomalyRule(RuleBase):
    rule_id = "ML_FLOW_ANOMALY"
    name = "ML flow anomaly"
    category = "behavior"
    severity = "HIGH"
    threshold = 80
    time_window = 60

    def __init__(
        self,
        *,
        detector: IsolationForestFlowDetector | None = None,
        model_path: str | None = None,
        enabled: bool | None = None,
        threshold: int | None = None,
        time_window: int | None = None,
        severity: str | None = None,
    ) -> None:
        super().__init__(enabled=enabled, threshold=threshold, time_window=time_window, severity=severity)
        self.extractor = FlowFeatureExtractor(time_window=self.time_window)
        self.detector = detector or IsolationForestFlowDetector(model_path=DEFAULT_MODEL_PATH if model_path is None else model_path)
        self.detector.load()

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        feature = self.extractor.observe(packet)
        result = self.detector.score_feature(feature)
        if result.score < self.threshold:
            return []

        reasons = result.reasons or ["flow behavior differs from local baseline"]
        return [
            self.create_alert(
                packet,
                alert_type="ML_ANOMALY",
                severity="CRITICAL" if result.score >= 95 else self.severity,
                description="Flow-level anomaly model assigned a high risk score to this host flow.",
                evidence=(
                    f"score={result.score:.1f}; backend={result.backend}; "
                    f"top_reasons={reasons[:3]}; src_ip={feature.src_ip}; dst_ip={feature.dst_ip}; "
                    f"window={feature.window_seconds}s; packets={feature.packet_count}; bytes={feature.byte_count}; "
                    f"unique_dst_ports={feature.unique_dst_ports}; unique_dst_ips={feature.unique_dst_ips}"
                ),
            )
        ]

    def save_model(self) -> None:
        self.detector.save()

    def reset(self) -> None:
        self.extractor.reset()
        self.detector.reset()
