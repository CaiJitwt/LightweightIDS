from __future__ import annotations

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class BruteForceRule(RuleBase):
    rule_id = "BRUTE_FORCE"
    name = "暴力破解连接检测"
    category = "authentication"
    severity = "HIGH"

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        return []
