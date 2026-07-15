from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord
from utils.ip_utils import is_private_ip, is_public_ip


@dataclass(frozen=True)
class OutboundHit:
    timestamp: float
    src_port: int | None = None


class AbnormalOutboundRule(RuleBase):
    rule_id = "ABNORMAL_OUTBOUND"
    name = "Abnormal outbound traffic"
    category = "behavior"
    severity = "HIGH"
    threshold = 4
    time_window = 300

    COMMON_OUTBOUND_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 853, 12202, 13203}
    HIGH_RISK_PORTS = {1337, 31337, 4444, 5555, 6666, 6667, 7777, 9001}

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hits: dict[tuple[str, str, int | None, str], deque[OutboundHit]] = defaultdict(deque)
        self._uncommon_connections: dict[tuple[str, str, int | None, str], deque[OutboundHit]] = defaultdict(deque)
        self._last_flow_seen: dict[tuple[str, str, int | None, int | None, str], float] = {}
        self._last_uncommon_alert: dict[tuple[str, str, int | None, str], float] = {}

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not self._is_internal_to_public(packet):
            return []

        alerts: list[AlertRecord] = []
        connection_start = self._is_connection_start(packet)
        uncommon_count = self._track_uncommon_connections(packet) if connection_start else None
        if uncommon_count is not None:
            description = (
                "Internal host connected to a high-risk public service port."
                if packet.dst_port in self.HIGH_RISK_PORTS
                else "Internal host repeatedly opened connections to a public address on an uncommon port."
            )
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="NON_STANDARD_OUTBOUND",
                    description=description,
                    evidence=(
                        f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
                        f"dst_port={packet.dst_port}; protocol={packet.protocol}; "
                        f"distinct_connections={uncommon_count}"
                    ),
                )
            )

        heartbeat = self._track_heartbeat(packet) if connection_start else None
        if heartbeat is not None:
            avg_interval, jitter, sample_count = heartbeat
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="C2_HEARTBEAT_SUSPECTED",
                    description="Repeated outbound connections show a fixed-interval heartbeat pattern.",
                    evidence=(
                        f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; dst_port={packet.dst_port}; "
                        f"protocol={packet.protocol}; samples={sample_count}; "
                        f"avg_interval={avg_interval:.1f}s; jitter={jitter:.1f}s"
                    ),
                )
            )

        return alerts

    def reset(self) -> None:
        self._hits.clear()
        self._uncommon_connections.clear()
        self._last_flow_seen.clear()
        self._last_uncommon_alert.clear()

    def _is_internal_to_public(self, packet: PacketRecord) -> bool:
        return bool(packet.src_ip and packet.dst_ip and is_private_ip(packet.src_ip) and is_public_ip(packet.dst_ip))

    def _track_heartbeat(self, packet: PacketRecord) -> tuple[float, float, int] | None:
        now = self.packet_time(packet)
        key = (packet.src_ip or "", packet.dst_ip or "", packet.dst_port, packet.protocol)
        hits = self._hits[key]
        hits.append(OutboundHit(timestamp=now))
        self._prune(hits, now)

        sample_count = len(hits)
        if sample_count < self.threshold:
            return None

        recent = list(hits)[-self.threshold :]
        intervals = [
            recent[index].timestamp - recent[index - 1].timestamp
            for index in range(1, len(recent))
        ]
        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)
        jitter = max(intervals) - min(intervals)
        allowed_jitter = max(2.0, avg_interval * 0.2)
        if 3 <= avg_interval <= self.time_window and jitter <= allowed_jitter:
            return avg_interval, jitter, sample_count
        return None

    def _track_uncommon_connections(self, packet: PacketRecord) -> int | None:
        if packet.dst_port is None:
            return None
        if packet.dst_port in self.HIGH_RISK_PORTS:
            return 1
        return None

    def _is_connection_start(self, packet: PacketRecord) -> bool:
        now = self.packet_time(packet)
        key = (
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        )
        previous = self._last_flow_seen.get(key)
        self._last_flow_seen[key] = now

        flags = (packet.tcp_flags or "").upper()
        if "S" in flags and "A" not in flags:
            return previous is None or now - previous >= 3
        return previous is None or now - previous > self.time_window

    def _prune(self, hits: deque[OutboundHit], now: float) -> None:
        while hits and now - hits[0].timestamp > self.time_window:
            hits.popleft()
