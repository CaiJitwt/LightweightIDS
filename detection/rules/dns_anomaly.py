from __future__ import annotations

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class DnsAnomalyRule(RuleBase):
    rule_id = "DNS_ANOMALY"
    name = "DNS 异常检测"
    category = "dns"
    severity = "MEDIUM"

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        return []
