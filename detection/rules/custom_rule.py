from __future__ import annotations

from detection.rule_base import RuleBase
from models import AlertRecord, CustomRuleRecord, PacketRecord


class CustomRule(RuleBase):
    category = "custom"

    def __init__(self, record: CustomRuleRecord) -> None:
        super().__init__(enabled=record.enabled, severity=record.severity)
        self.record = record
        self.rule_id = f"CUSTOM_{record.id}" if record.id is not None else "CUSTOM_NEW"
        self.name = record.name or self.rule_id
        self.severity = record.severity.upper()

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not self.enabled or not self._matches(packet):
            return []

        evidence = (
            f"protocol={packet.protocol}; src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"src_port={packet.src_port}; dst_port={packet.dst_port}; keyword={self.record.keyword or ''}"
        )
        return [
            self.create_alert(
                packet,
                alert_type="CUSTOM_RULE",
                description=self.record.description or f"命中自定义规则：{self.name}",
                evidence=evidence,
            )
        ]

    def _matches(self, packet: PacketRecord) -> bool:
        if self.record.protocol and packet.protocol.upper() != self.record.protocol.upper():
            return False
        if self.record.src_ip and packet.src_ip != self.record.src_ip:
            return False
        if self.record.dst_ip and packet.dst_ip != self.record.dst_ip:
            return False
        if self.record.src_port is not None and packet.src_port != self.record.src_port:
            return False
        if self.record.dst_port is not None and packet.dst_port != self.record.dst_port:
            return False
        if self.record.keyword:
            haystack = " ".join(
                value or ""
                for value in [
                    packet.raw_summary,
                    packet.dns_query,
                    packet.http_method,
                    packet.http_host,
                    packet.http_path,
                ]
            ).lower()
            if self.record.keyword.lower() not in haystack:
                return False
        return True
