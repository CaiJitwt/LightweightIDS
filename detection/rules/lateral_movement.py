from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from detection.rule_base import RuleBase
from detection.rules.payload_utils import packet_text
from models import AlertRecord, PacketRecord
from utils.ip_utils import is_private_ip


@dataclass(frozen=True)
class LateralHit:
    timestamp: float
    dst_ip: str
    dst_port: int | None


class LateralMovementRule(RuleBase):
    rule_id = "LATERAL_MOVEMENT"
    name = "Lateral movement"
    category = "behavior"
    severity = "CRITICAL"
    threshold = 5
    time_window = 60

    LATERAL_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
    ADMIN_SHARE_MARKERS = ("\\\\admin$", "\\admin$", "\\\\c$", "\\c$")

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hits: dict[tuple[str, int | None], deque[LateralHit]] = defaultdict(deque)
        self._target_hits: dict[tuple[str, str], deque[LateralHit]] = defaultdict(deque)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        if self._contains_admin_share(packet):
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="ADMIN_SHARE_ACCESS",
                    description="Traffic contains access to Windows administrative shares.",
                    evidence=f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; marker=admin_share",
                )
            )

        if not self._is_internal_lateral_service(packet):
            return alerts

        now = self.packet_time(packet)
        key = (packet.src_ip or "", packet.dst_port)
        hits = self._hits[key]
        hits.append(LateralHit(timestamp=now, dst_ip=packet.dst_ip or "", dst_port=packet.dst_port))
        self._prune(hits, now)

        target_key = (packet.src_ip or "", packet.dst_ip or "")
        target_hits = self._target_hits[target_key]
        target_hits.append(LateralHit(timestamp=now, dst_ip=packet.dst_ip or "", dst_port=packet.dst_port))
        self._prune(target_hits, now)

        targets = sorted({hit.dst_ip for hit in hits if hit.dst_ip})
        if len(targets) >= self.threshold:
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="LATERAL_MOVEMENT",
                    description="Internal host reached many internal targets on remote administration ports.",
                    evidence=(
                        f"src_ip={packet.src_ip}; dst_port={packet.dst_port}; "
                        f"distinct_targets={len(targets)}; targets={targets}; "
                        f"time_window={self.time_window}s"
                    ),
                )
            )

        service_ports = sorted({hit.dst_port for hit in target_hits if hit.dst_port is not None})
        if len(target_hits) >= self.threshold and len(service_ports) >= 2:
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="REMOTE_SERVICE_LATERAL_MOVEMENT",
                    description="Internal host repeatedly used multiple remote administration services against one peer.",
                    evidence=(
                        f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
                        f"event_count={len(target_hits)}; service_ports={service_ports}; "
                        f"threshold={self.threshold}; time_window={self.time_window}s"
                    ),
                )
            )
            target_hits.clear()

        return alerts

    def reset(self) -> None:
        self._hits.clear()
        self._target_hits.clear()

    def _is_internal_lateral_service(self, packet: PacketRecord) -> bool:
        return bool(
            packet.src_ip
            and packet.dst_ip
            and packet.dst_port in self.LATERAL_PORTS
            and is_private_ip(packet.src_ip)
            and is_private_ip(packet.dst_ip)
            and packet.src_ip != packet.dst_ip
        )

    def _contains_admin_share(self, packet: PacketRecord) -> bool:
        if packet.dst_port != 445 and packet.src_port != 445:
            return False
        text = packet_text(packet).replace("/", "\\")
        return any(marker in text for marker in self.ADMIN_SHARE_MARKERS)

    def _prune(self, hits: deque[LateralHit], now: float) -> None:
        while hits and now - hits[0].timestamp > self.time_window:
            hits.popleft()
