from __future__ import annotations

import re

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
    protocols = {"HTTP", "HTTPS"}

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

    # Regex patterns for event handlers, SVG/iframe injection, HTML entity
    # encoding, fromCharCode/atob/btoa, CSS expression, and data URI smuggling.
    REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("script_tag", re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)),
        ("script_src", re.compile(r"<\s*script[^>]*src\s*=", re.IGNORECASE)),
        ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
        ("onclick", re.compile(r"\bonclick\s*=", re.IGNORECASE)),
        ("onmouseover", re.compile(r"\bonmouseover\s*=", re.IGNORECASE)),
        ("onfocus", re.compile(r"\bonfocus\s*=", re.IGNORECASE)),
        ("oninput", re.compile(r"\boninput\s*=", re.IGNORECASE)),
        ("prompt_call", re.compile(r"\bprompt\s*\([^)]*\)", re.IGNORECASE)),
        ("confirm_call", re.compile(r"\bconfirm\s*\([^)]*\)", re.IGNORECASE)),
        ("document_write", re.compile(r"\bdocument\s*\.\s*write\s*\(", re.IGNORECASE)),
        ("settimeout", re.compile(r"\bsetTimeout\s*\([^)]*\)", re.IGNORECASE)),
        ("img_onerror", re.compile(r"<\s*img[^>]*onerror\s*=", re.IGNORECASE)),
        ("img_src_x", re.compile(r"<\s*img[^>]*src\s*=\s*[\"']?\s*x\s*[\"']?", re.IGNORECASE)),
        ("svg_onload", re.compile(r"<\s*svg[^>]*onload\s*=", re.IGNORECASE)),
        ("iframe_tag", re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE)),
        ("entity_encoded", re.compile(r"&#x?[0-9a-fA-F]+;", re.IGNORECASE)),
        ("fromcharcode", re.compile(r"\bString\s*\.\s*fromCharCode\s*\(", re.IGNORECASE)),
        ("atob_btoa", re.compile(r"\batob\s*\(|\bbtoa\s*\(", re.IGNORECASE)),
        ("expression_css", re.compile(r"\bexpression\s*\([^)]*\)", re.IGNORECASE)),
        ("data_uri_html", re.compile(r"data\s*:\s*text/html", re.IGNORECASE)),
        ("onerror", re.compile(r"\bonerror\s*=", re.IGNORECASE)),
        ("onload", re.compile(r"\bonload\s*=", re.IGNORECASE)),
        ("alert_call", re.compile(r"\balert\s*\([^)]*\)", re.IGNORECASE)),
        ("document_cookie", re.compile(r"\bdocument\s*\.\s*cookie\b", re.IGNORECASE)),
        ("eval_call", re.compile(r"\beval\s*\([^)]*\)", re.IGNORECASE)),
        ("srcdoc", re.compile(r"\bsrcdoc\s*=", re.IGNORECASE)),
        ("vbscript_uri", re.compile(r"vbscript\s*:", re.IGNORECASE)),
        ("meta_refresh", re.compile(r"<\s*meta[^>]*http-equiv\s*=\s*[\"']?refresh", re.IGNORECASE)),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []

        text = packet_text(packet)
        matches = matched_keywords(text, self.KEYWORDS)
        matches.extend(name for name, pattern in self.REGEX_PATTERNS if pattern.search(text))
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
