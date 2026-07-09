from __future__ import annotations

from detection.rule_base import RuleBase
from detection.window_counter import WindowCounter
from models import AlertRecord, PacketRecord


class IcmpFloodRule(RuleBase):
    rule_id = "ICMP_FLOOD"
    name = "ICMP flood detection"
    category = "flood"
    severity = "MEDIUM"
    threshold = 50
    time_window = 10

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._counter = WindowCounter(self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol != "ICMP" or not packet.src_ip or not packet.dst_ip:
            return []

        now = self.packet_time(packet)
        key = (packet.src_ip, packet.dst_ip)
        count = self._counter.add(key, now)
        if count < self.threshold:
            return []

        evidence = (
            f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"icmp_count={count}; time_window={self.time_window}s"
        )
        return [
            self.create_alert(
                packet,
                alert_type="ICMP_FLOOD",
                description=f"Source IP sent many ICMP packets to the same target within {self.time_window} seconds.",
                evidence=evidence,
            )
        ]

    def reset(self) -> None:
        self._counter = WindowCounter(self.time_window)

    def set_time_window(self, time_window: int) -> None:
        super().set_time_window(time_window)
        self._counter = WindowCounter(self.time_window)
