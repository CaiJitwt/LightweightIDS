from __future__ import annotations

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class SensitivePortRule(RuleBase):
    rule_id = "SENSITIVE_PORT"
    name = "Sensitive port access"
    category = "policy"
    severity = "MEDIUM"
    threshold = 1
    time_window = 0

    DEFAULT_SENSITIVE_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        445: "SMB",
        1433: "SQL Server",
        3306: "MySQL",
        3389: "RDP",
        6379: "Redis",
        9200: "Elasticsearch",
    }

    def __init__(self, sensitive_ports: dict[int, str] | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.sensitive_ports = sensitive_ports or self.DEFAULT_SENSITIVE_PORTS

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.dst_port is None or packet.dst_port not in self.sensitive_ports:
            return []

        service = self.sensitive_ports[packet.dst_port]
        evidence = (
            f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"dst_port={packet.dst_port}; service={service}; protocol={packet.protocol}"
        )
        return [
            self.create_alert(
                packet,
                alert_type="SENSITIVE_PORT_ACCESS",
                description=f"Detected access to sensitive service port {packet.dst_port}/{service}.",
                evidence=evidence,
            )
        ]
