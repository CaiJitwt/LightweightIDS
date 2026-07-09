from __future__ import annotations

from detection.baseline import BaselineManager, BaselineObservation
from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class BandwidthSpikeRule(RuleBase):
    rule_id = "BANDWIDTH_SPIKE"
    name = "Bandwidth spike"
    category = "behavior"
    severity = "HIGH"
    threshold = 4
    time_window = 60

    def __init__(self, *, min_history: int = 5, min_extra_bytes: int = 4000, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.min_history = min_history
        self.min_extra_bytes = min_extra_bytes
        self.baseline_manager = BaselineManager(window_seconds=self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        observation = self.baseline_manager.observe(packet)
        if not self._is_spike(observation):
            return []

        current = observation.current
        historical = observation.historical_mean
        assert current is not None and historical is not None

        return [
            self.create_alert(
                packet,
                alert_type="BANDWIDTH_SPIKE",
                description="Host bandwidth usage exceeded its historical baseline.",
                evidence=(
                    f"src_ip={packet.src_ip}; window={self.time_window}s; "
                    f"bytes_current={current.bytes_per_window}; bytes_baseline={historical.bytes_per_window}; "
                    f"avg_length_current={current.avg_packet_length:.1f}; "
                    f"avg_length_baseline={historical.avg_packet_length:.1f}"
                ),
            )
        ]

    def reset(self) -> None:
        self.baseline_manager.reset()

    def _is_spike(self, observation: BaselineObservation) -> bool:
        if (
            observation.current is None
            or observation.historical_mean is None
            or observation.history_count < self.min_history
        ):
            return False

        baseline_bytes = observation.historical_mean.bytes_per_window
        current_bytes = observation.current.bytes_per_window
        if baseline_bytes <= 0:
            return False
        required = max(baseline_bytes * max(2, self.threshold), baseline_bytes + self.min_extra_bytes)
        return current_bytes >= required
