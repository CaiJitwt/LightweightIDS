from __future__ import annotations

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class HttpSuspiciousRule(RuleBase):
    rule_id = "HTTP_SUSPICIOUS"
    name = "HTTP 可疑请求检测"
    category = "http"
    severity = "MEDIUM"

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        return []
