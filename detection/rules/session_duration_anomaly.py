from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


@dataclass(slots=True)
class SessionState:
    first_seen: float
    last_seen: float
    last_alert_duration: float = 0.0
    alerted: bool = False


class SessionDurationAnomalyRule(RuleBase):
    rule_id = "SESSION_DURATION_ANOMALY"
    name = "Session duration anomaly"
    category = "behavior"
    severity = "MEDIUM"
    threshold = 3
    time_window = 600
    IGNORED_PROTOCOLS = {"DNS", "HTTP", "HTTPS", "LLMNR", "MDNS", "QUIC", "TLS"}
    MONITORED_PORTS = {22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017}

    def __init__(self, *, min_history: int = 4, min_extra_seconds: float = 30.0, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.min_history = min_history
        self.min_extra_seconds = min_extra_seconds
        self._sessions: dict[tuple[str, str, int | None, str], SessionState] = {}
        self._duration_history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=50))

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if (packet.protocol or "").upper() in self.IGNORED_PROTOCOLS:
            return []
        if packet.src_port not in self.MONITORED_PORTS and packet.dst_port not in self.MONITORED_PORTS:
            return []
        key = self._session_key(packet)
        if key is None:
            return []

        now = self.packet_time(packet)
        state = self._sessions.get(key)
        if state is None or now - state.last_seen > self.time_window:
            self._sessions[key] = SessionState(first_seen=now, last_seen=now)
            return []

        state.last_seen = now
        duration = state.last_seen - state.first_seen
        history = self._duration_history[packet.src_ip or ""]
        historical_average = self._average(history)
        should_alert = self._is_duration_anomaly(duration, historical_average, len(history), state)
        if duration > 0:
            history.append(duration)

        if not should_alert:
            return []

        state.last_alert_duration = duration
        state.alerted = True
        return [
            self.create_alert(
                packet,
                alert_type="SESSION_DURATION_ANOMALY",
                description="Observed session duration exceeded the host historical average.",
                evidence=(
                    f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; dst_port={packet.dst_port}; "
                    f"duration={duration:.1f}s; baseline_duration={historical_average:.1f}s; "
                    f"history_samples={len(history)}"
                ),
            )
        ]

    def reset(self) -> None:
        self._sessions.clear()
        self._duration_history.clear()

    def _session_key(self, packet: PacketRecord) -> tuple[str, str, int | None, str] | None:
        if not packet.src_ip or not packet.dst_ip:
            return None
        return (packet.src_ip, packet.dst_ip, packet.dst_port, packet.protocol)

    def _average(self, values: deque[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    def _is_duration_anomaly(
        self,
        duration: float,
        historical_average: float,
        history_count: int,
        state: SessionState,
    ) -> bool:
        if history_count < self.min_history or historical_average <= 0:
            return False
        if state.alerted:
            return False
        required = max(historical_average * max(2, self.threshold), historical_average + self.min_extra_seconds)
        if duration < required:
            return False
        return duration - state.last_alert_duration >= max(1.0, historical_average)
