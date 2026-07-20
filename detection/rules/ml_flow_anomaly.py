from __future__ import annotations

from detection.features import FlowFeature, FlowFeatureExtractor
from detection.ml import DEFAULT_MODEL_PATH, IsolationForestFlowDetector
from detection.rule_base import RuleBase
from detection.traffic_direction import is_likely_server_response
from models import AlertRecord, PacketRecord


class MlFlowAnomalyRule(RuleBase):
    rule_id = "ML_FLOW_ANOMALY"
    name = "ML flow anomaly"
    category = "behavior"
    severity = "HIGH"
    threshold = 95
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
        self._alerted_windows: set[tuple[str, str, float]] = set()

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if is_likely_server_response(packet):
            return []

        feature = self.extractor.observe(packet)
        result = self.detector.score_feature(feature)
        window_key = (feature.src_ip, feature.dst_ip, feature.window_start)
        self._prune_alerted_windows(feature.window_start)
        if result.score < self.threshold or window_key in self._alerted_windows:
            return []
        if not self._has_actionable_reason(feature, result.reasons, result.score):
            return []

        reasons = result.reasons or ["flow behavior differs from local baseline"]
        self._alerted_windows.add(window_key)
        return [
            self.create_alert(
                packet,
                alert_type="ML_ANOMALY",
                severity=self.severity,
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
        self._alerted_windows.clear()

    def _has_actionable_reason(self, feature: FlowFeature, reasons: list[str], score: float) -> bool:
        # A high model score alone is noisy during baseline warm-up. Require a
        # concrete behavior pattern before promoting it to an IDS alert.
        port_spread = feature.unique_dst_ports
        syn_count = feature.syn_count
        sensitive_count = feature.sensitive_port_count
        icmp_count = feature.icmp_count
        packet_count = feature.packet_count
        byte_count = feature.byte_count

        scan_pattern = port_spread >= 8 and syn_count >= 4
        sensitive_service_sweep = port_spread >= 4 and sensitive_count >= 4 and syn_count >= 3
        icmp_burst = icmp_count >= 50
        mature_model_outlier = (
            score >= 98
            and packet_count >= 50
            and byte_count >= 1_048_576
            and any(reason.startswith("isolation_forest_score") for reason in reasons)
        )
        return scan_pattern or sensitive_service_sweep or icmp_burst or mature_model_outlier

    def _prune_alerted_windows(self, current_window: float) -> None:
        oldest = current_window - self.time_window * 2
        self._alerted_windows = {key for key in self._alerted_windows if key[2] >= oldest}
