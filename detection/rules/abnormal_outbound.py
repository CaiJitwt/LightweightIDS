from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord
from utils.ip_utils import is_private_ip, is_public_ip


@dataclass(frozen=True)
class OutboundHit:
    timestamp: float


class AbnormalOutboundRule(RuleBase):
    rule_id = "ABNORMAL_OUTBOUND"
    name = "Abnormal outbound traffic"
    category = "behavior"
    severity = "HIGH"
    threshold = 4
    time_window = 300

    COMMON_OUTBOUND_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 853}

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hits: dict[tuple[str, str, int | None, str], deque[OutboundHit]] = defaultdict(deque)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not self._is_internal_to_public(packet):
            return []

        alerts: list[AlertRecord] = []
        if packet.dst_port is not None and packet.dst_port not in self.COMMON_OUTBOUND_PORTS:
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="NON_STANDARD_OUTBOUND",
                    description="Internal host connected to a public address on an uncommon outbound port.",
                    evidence=(
                        f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
                        f"dst_port={packet.dst_port}; protocol={packet.protocol}"
                    ),
                )
            )

        heartbeat = self._track_heartbeat(packet)
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

    def _prune(self, hits: deque[OutboundHit], now: float) -> None:
        while hits and now - hits[0].timestamp > self.time_window:
            hits.popleft()
