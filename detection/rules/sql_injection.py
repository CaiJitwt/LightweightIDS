from __future__ import annotations

import re

from detection.rule_base import RuleBase
from detection.rules.payload_utils import packet_text
from models import AlertRecord, PacketRecord


class SqlInjectionRule(RuleBase):
    rule_id = "SQL_INJECTION"
    name = "SQL injection detection"
    category = "web"
    severity = "CRITICAL"
    threshold = 1
    time_window = 0

    KEYWORDS = [
        "union select",
        "drop table",
        "insert into",
        "select from",
        "xp_cmdshell",
        "information_schema",
        "sleep(",
        "benchmark(",
        "load_file(",
    ]
    REGEX_PATTERNS = [
        re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
        re.compile(r"\band\s+1\s*=\s*1\b", re.IGNORECASE),
        re.compile(r"'\s*or\s*'[^']*'\s*=\s*'", re.IGNORECASE),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []

        text = packet_text(packet)
        matches = [keyword for keyword in self.KEYWORDS if keyword in text]
        matches.extend(pattern.pattern for pattern in self.REGEX_PATTERNS if pattern.search(text))
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="SQL_INJECTION",
                description="Detected suspicious SQL injection indicators.",
                evidence=f"matched={matches}; target={packet.http_host or packet.dst_ip}; path={packet.http_path or ''}",
            )
        ]
