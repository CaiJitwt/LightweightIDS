from __future__ import annotations

from detection.baseline import BaselineManager, BaselineObservation
from detection.rule_base import RuleBase
from models import AlertRecord, BaselineRecord, PacketRecord


class BaselineDeviationRule(RuleBase):
    rule_id = "BASELINE_DEVIATION"
    name = "Baseline deviation"
    category = "behavior"
    severity = "HIGH"
    threshold = 3
    time_window = 60

    def __init__(self, *, min_history: int = 8, minimum_deviations: int = 2, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.min_history = min_history
        self.minimum_deviations = max(1, minimum_deviations)
        self.baseline_manager = BaselineManager(window_seconds=self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        observation = self.baseline_manager.observe(packet)
        if not self._has_baseline(observation):
            return []

        current = observation.current
        historical = observation.historical_mean
        assert current is not None and historical is not None

        deviations = self._deviations(current, historical)
        if len(deviations) < self.minimum_deviations:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="BASELINE_DEVIATION",
                description="Host activity exceeded its historical behavior baseline.",
                evidence=(
                    f"src_ip={packet.src_ip}; window={self.time_window}s; "
                    f"history_samples={observation.history_count}; deviations={'; '.join(deviations)}"
                ),
            )
        ]

    def reset(self) -> None:
        self.baseline_manager.reset()

    def _has_baseline(self, observation: BaselineObservation) -> bool:
        return bool(
            observation.current is not None
            and observation.historical_mean is not None
            and observation.history_count >= self.min_history
        )

    def _deviations(self, current: BaselineRecord, historical: BaselineRecord) -> list[str]:
        factor = max(2, self.threshold)
        checks = [
            ("packet_count", current.packet_count, historical.packet_count, 5),
            ("unique_dst_ports", current.unique_dst_ports, historical.unique_dst_ports, 3),
            ("unique_dst_ips", current.unique_dst_ips, historical.unique_dst_ips, 3),
            ("bytes_per_window", current.bytes_per_window, historical.bytes_per_window, 5000),
        ]

        deviations = []
        for label, current_value, baseline_value, minimum_delta in checks:
            if baseline_value <= 0:
                continue
            required = max(baseline_value * factor, baseline_value + minimum_delta)
            if current_value >= required:
                deviations.append(f"{label} current={current_value} baseline={baseline_value}")
        return deviations
