from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


@dataclass(frozen=True)
class HostHit:
    timestamp: float
    dst_ip: str


class HostScanRule(RuleBase):
    rule_id = "HOST_SCAN"
    name = "Host scan"
    category = "scan"
    severity = "HIGH"
    threshold = 30
    time_window = 10

    SCANNED_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "DNS"}

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hits: dict[str, deque[HostHit]] = defaultdict(deque)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not packet.src_ip or not packet.dst_ip or packet.src_ip == packet.dst_ip:
            return []
        if packet.protocol not in self.SCANNED_PROTOCOLS:
            return []

        now = self.packet_time(packet)
        hits = self._hits[packet.src_ip]
        hits.append(HostHit(timestamp=now, dst_ip=packet.dst_ip))
        self._prune(hits, now)

        targets = sorted({hit.dst_ip for hit in hits})
        if len(targets) < self.threshold:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="HOST_SCAN",
                description="Source host contacted many different destination hosts in a short time window.",
                evidence=(
                    f"src_ip={packet.src_ip}; distinct_targets={len(targets)}; "
                    f"targets={targets}; time_window={self.time_window}s"
                ),
            )
        ]

    def reset(self) -> None:
        self._hits.clear()

    def _prune(self, hits: deque[HostHit], now: float) -> None:
        while hits and now - hits[0].timestamp > self.time_window:
            hits.popleft()
