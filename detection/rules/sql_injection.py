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
    REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # Named regex patterns for time-based blind, error-based, stacked queries,
        # wide-byte encoding, hex encoding, and tautology variants.
        ("union_select", re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE)),
        ("tautology_quote", re.compile(r"'\s*OR\s+'1'\s*=\s*'1|'\s*OR\s+1\s*=\s*1|'\s*OR\s+'a'\s*=\s*'a", re.IGNORECASE)),
        ("numeric_tautology", re.compile(r"\bOR\s+1\s*=\s*1\b|\bAND\s+1\s*=\s*1\b", re.IGNORECASE)),
        ("sql_comment", re.compile(r"--\s|--$|/\*.*\*/|#\s*$", re.IGNORECASE)),
        ("drop_table", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
        ("alter_table", re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE)),
        ("truncate_table", re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE)),
        ("sp_execute", re.compile(r"\bsp_executesql\b|\bEXEC\s*\(|\bEXECUTE\s*\(", re.IGNORECASE)),
        ("time_based", re.compile(r"\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY\b", re.IGNORECASE)),
        ("file_ops", re.compile(r"\bLOAD_FILE\s*\(|\bINTO\s+(OUTFILE|DUMPFILE)\b|\bOUTFILE\b", re.IGNORECASE)),
        ("error_based", re.compile(r"\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\(|\bFLOOR\s*\(\s*RAND\s*\(\s*\)", re.IGNORECASE)),
        ("stacked_query", re.compile(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)", re.IGNORECASE)),
        ("wide_byte", re.compile(r"%df%27|%bf%27|%df'|%bf'", re.IGNORECASE)),
        ("hex_encode", re.compile(r"0x[0-9a-fA-F]{6,}", re.IGNORECASE)),
        ("or_tautology", re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE)),
        ("quote_tautology", re.compile(r"'\s*OR\s*'[^']*'\s*=\s*'", re.IGNORECASE)),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []

        text = packet_text(packet)
        matches = [keyword for keyword in self.KEYWORDS if keyword in text]
        matches.extend(name for name, pattern in self.REGEX_PATTERNS if pattern.search(text))
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
