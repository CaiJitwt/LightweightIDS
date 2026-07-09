from __future__ import annotations

from detection.rule_base import RuleBase
from detection.rules.payload_utils import matched_keywords, packet_text
from models import AlertRecord, PacketRecord


class HttpSuspiciousRule(RuleBase):
    rule_id = "HTTP_SUSPICIOUS"
    name = "Suspicious HTTP request"
    category = "web"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    KEYWORDS = [
        "../",
        "..\\",
        "%2e%2e",
        "/etc/passwd",
        "boot.ini",
        "web.config",
        "169.254.169.254",
        "metadata.google.internal",
        "file://",
        "php://",
        "expect://",
        "gopher://",
        "jndi:",
        "ysoserial",
        "${jndi",
        "; id",
        "| id",
        "`id`",
        "; ls",
        "| ls",
        "`ls`",
        "/admin",
        "/wp-admin",
        "/.env",
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
                alert_type="HTTP_SUSPICIOUS",
                description="Detected directory traversal, SSRF, file inclusion or suspicious administration path indicators.",
                evidence=f"matched={matches}; host={packet.http_host or ''}; path={packet.http_path or ''}",
            )
        ]
