from __future__ import annotations

from detection.rule_base import RuleBase
from detection.rules.payload_utils import matched_keywords, packet_text
from models import AlertRecord, PacketRecord


class XssRule(RuleBase):
    rule_id = "XSS"
    name = "XSS detection"
    category = "web"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    KEYWORDS = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "alert(",
        "document.cookie",
        "document.domain",
        "<img",
        "<iframe",
        "eval(",
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []

        matches = matched_keywords(packet_text(packet), self.KEYWORDS)
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="XSS",
                description="Detected suspicious cross-site scripting indicators.",
                evidence=f"matched={matches}; host={packet.http_host or ''}; path={packet.http_path or ''}",
            )
        ]
