from __future__ import annotations

from detection.rule_base import RuleBase
from detection.window_counter import WindowCounter
from models import AlertRecord, PacketRecord


class BruteForceRule(RuleBase):
    rule_id = "BRUTE_FORCE"
    name = "Brute-force connection detection"
    category = "authentication"
    severity = "HIGH"
    threshold = 10
    time_window = 10

    WATCHED_PORTS = {
        21: "FTP",
        22: "SSH",
        389: "LDAP",
        1433: "SQL Server",
        3306: "MySQL",
        3389: "RDP",
    }

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._counter = WindowCounter(self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not packet.src_ip or not packet.dst_ip or packet.dst_port not in self.WATCHED_PORTS:
            return []

        now = self.packet_time(packet)
        key = (packet.src_ip, packet.dst_ip, packet.dst_port)
        count = self._counter.add(key, now)
        if count < self.threshold:
            return []

        service = self.WATCHED_PORTS[packet.dst_port]
        return [
            self.create_alert(
                packet,
                alert_type="BRUTE_FORCE",
                description=f"Detected many {service} connection attempts in a short time window.",
                evidence=(
                    f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; dst_port={packet.dst_port}; "
                    f"service={service}; count={count}; time_window={self.time_window}s"
                ),
            )
        ]

    def reset(self) -> None:
        self._counter = WindowCounter(self.time_window)

    def set_time_window(self, time_window: int) -> None:
        super().set_time_window(time_window)
        self._counter = WindowCounter(self.time_window)
