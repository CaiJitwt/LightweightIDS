from __future__ import annotations

from detection.rule_base import RuleBase
from detection.rules.payload_utils import matched_keywords, packet_text
from models import AlertRecord, PacketRecord


class MaliciousCommandRule(RuleBase):
    rule_id = "MALICIOUS_COMMAND"
    name = "Malicious command detection"
    category = "web"
    severity = "CRITICAL"
    threshold = 1
    time_window = 0

    KEYWORDS = [
        "whoami",
        "net user",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "bash -i",
        "/dev/tcp",
        "powershell -enc",
        "powershell.exe -enc",
        "wget ",
        "curl ",
        "certutil",
        "nc -e",
        "ncat",
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        text = packet_text(packet)
        matches = matched_keywords(text, self.KEYWORDS)
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="MALICIOUS_COMMAND",
                description="Detected suspicious system command or download-execute indicators.",
                evidence=f"matched={matches}; src={packet.src_ip}; dst={packet.dst_ip}",
            )
        ]
