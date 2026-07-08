from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


@dataclass(frozen=True)
class PortHit:
    timestamp: float
    dst_port: int


class PortScanRule(RuleBase):
    rule_id = "PORT_SCAN"
    name = "端口扫描检测"
    category = "scan"
    severity = "HIGH"
    threshold = 20
    time_window = 10

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hits: dict[tuple[str, str], deque[PortHit]] = defaultdict(deque)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not packet.src_ip or not packet.dst_ip or packet.dst_port is None:
            return []
        if packet.protocol not in {"TCP", "UDP", "HTTP", "DNS"}:
            return []

        now = self.packet_time(packet)
        key = (packet.src_ip, packet.dst_ip)
        hits = self._hits[key]
        hits.append(PortHit(timestamp=now, dst_port=packet.dst_port))
        self._prune(hits, now)

        ports = sorted({hit.dst_port for hit in hits})
        if len(ports) < self.threshold:
            return []

        evidence = (
            f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"distinct_ports={len(ports)}; ports={ports}; time_window={self.time_window}s"
        )
        return [
            self.create_alert(
                packet,
                alert_type="PORT_SCAN",
                description=f"源 IP 在 {self.time_window} 秒内访问同一目标的 {len(ports)} 个不同端口。",
                evidence=evidence,
            )
        ]

    def reset(self) -> None:
        self._hits.clear()

    def _prune(self, hits: deque[PortHit], now: float) -> None:
        while hits and now - hits[0].timestamp > self.time_window:
            hits.popleft()
