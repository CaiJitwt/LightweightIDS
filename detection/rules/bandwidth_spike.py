from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


@dataclass(slots=True)
class ByteWindow:
    started_at: float
    byte_count: int = 0
    packet_count: int = 0


class BandwidthSpikeRule(RuleBase):
    rule_id = "BANDWIDTH_SPIKE"
    name = "Bandwidth spike"
    category = "behavior"
    severity = "MEDIUM"
    threshold = 8
    time_window = 60

    def __init__(
        self,
        *,
        min_history: int = 8,
        min_extra_bytes: int = 262_144,
        min_absolute_bytes: int = 1_048_576,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.min_history = min_history
        self.min_extra_bytes = min_extra_bytes
        self.min_absolute_bytes = min_absolute_bytes
        self._current: dict[str, ByteWindow] = {}
        self._history: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=30))

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not packet.src_ip:
            return []
        current, historical_bytes, history_count = self._observe(packet)
        if not self._is_spike(current.byte_count, historical_bytes, history_count):
            return []

        return [
            self.create_alert(
                packet,
                alert_type="BANDWIDTH_SPIKE",
                description="Host bandwidth usage exceeded its historical baseline.",
                evidence=(
                    f"src_ip={packet.src_ip}; window={self.time_window}s; "
                    f"bytes_current={current.byte_count}; bytes_baseline={historical_bytes:.0f}; "
                    f"packets_current={current.packet_count}; history_windows={history_count}"
                ),
            )
        ]

    def reset(self) -> None:
        self._current.clear()
        self._history.clear()

    def _observe(self, packet: PacketRecord) -> tuple[ByteWindow, float, int]:
        src_ip = packet.src_ip or ""
        now = self.packet_time(packet)
        window_start = now - (now % max(1, self.time_window))
        current = self._current.get(src_ip)
        if current is None or current.started_at != window_start:
            if current is not None and current.packet_count:
                self._history[src_ip].append(current.byte_count)
            current = ByteWindow(started_at=window_start)
            self._current[src_ip] = current

        current.byte_count += max(0, int(packet.length or 0))
        current.packet_count += 1
        history = self._history[src_ip]
        historical_bytes = mean(history) if history else 0.0
        return current, historical_bytes, len(history)

    def _is_spike(self, current_bytes: int, baseline_bytes: float, history_count: int) -> bool:
        if history_count < self.min_history:
            return False
        if baseline_bytes <= 0:
            return False
        if current_bytes < self.min_absolute_bytes:
            return False
        required = max(baseline_bytes * max(2, self.threshold), baseline_bytes + self.min_extra_bytes)
        return current_bytes >= required
