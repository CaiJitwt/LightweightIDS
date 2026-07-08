from __future__ import annotations

from detection.rule_base import RuleBase
from detection.window_counter import WindowCounter
from models import AlertRecord, PacketRecord


class SynFloodRule(RuleBase):
    rule_id = "SYN_FLOOD"
    name = "SYN Flood 检测"
    category = "flood"
    severity = "HIGH"
    threshold = 100
    time_window = 10

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._counter = WindowCounter(self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol != "TCP" or not packet.src_ip or not packet.dst_ip:
            return []
        if not self._is_syn_without_ack(packet.tcp_flags):
            return []

        now = self.packet_time(packet)
        key = (packet.src_ip, packet.dst_ip)
        count = self._counter.add(key, now)
        if count < self.threshold:
            return []

        evidence = (
            f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"syn_count={count}; time_window={self.time_window}s; tcp_flags={packet.tcp_flags}"
        )
        return [
            self.create_alert(
                packet,
                alert_type="SYN_FLOOD",
                description=f"源 IP 在 {self.time_window} 秒内向同一目标发送大量 TCP SYN 包。",
                evidence=evidence,
            )
        ]

    def reset(self) -> None:
        self._counter = WindowCounter(self.time_window)

    def set_time_window(self, time_window: int) -> None:
        super().set_time_window(time_window)
        self._counter = WindowCounter(self.time_window)

    def _is_syn_without_ack(self, flags: str | None) -> bool:
        if not flags:
            return False
        normalized = flags.upper()
        return "S" in normalized and "A" not in normalized
