from __future__ import annotations

import re

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class XssRule(RuleBase):
    rule_id = "XSS"
    name = "XSS 攻击检测"
    category = "injection"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    _PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # script 标签
        ("script_tag", re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)),
        ("script_src", re.compile(r"<\s*script[^>]*src\s*=", re.IGNORECASE)),
        # javascript 伪协议
        ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
        # 事件处理器
        ("onerror", re.compile(r"\bonerror\s*=", re.IGNORECASE)),
        ("onload", re.compile(r"\bonload\s*=", re.IGNORECASE)),
        ("onclick", re.compile(r"\bonclick\s*=", re.IGNORECASE)),
        ("onmouseover", re.compile(r"\bonmouseover\s*=", re.IGNORECASE)),
        ("onfocus", re.compile(r"\bonfocus\s*=", re.IGNORECASE)),
        ("oninput", re.compile(r"\boninput\s*=", re.IGNORECASE)),
        # 常见 XSS payload
        ("alert_call", re.compile(r"\balert\s*\([^)]*\)", re.IGNORECASE)),
        ("prompt_call", re.compile(r"\bprompt\s*\([^)]*\)", re.IGNORECASE)),
        ("confirm_call", re.compile(r"\bconfirm\s*\([^)]*\)", re.IGNORECASE)),
        ("document_cookie", re.compile(r"\bdocument\s*\.\s*cookie\b", re.IGNORECASE)),
        ("document_write", re.compile(r"\bdocument\s*\.\s*write\s*\(", re.IGNORECASE)),
        ("eval_call", re.compile(r"\beval\s*\([^)]*\)", re.IGNORECASE)),
        ("settimeout", re.compile(r"\bsetTimeout\s*\([^)]*\)", re.IGNORECASE)),
        # img 标签注入
        ("img_onerror", re.compile(r"<\s*img[^>]*onerror\s*=", re.IGNORECASE)),
        ("img_src_x", re.compile(r"<\s*img[^>]*src\s*=\s*[\"']?\s*x\s*[\"']?", re.IGNORECASE)),
        # svg 注入
        ("svg_onload", re.compile(r"<\s*svg[^>]*onload\s*=", re.IGNORECASE)),
        # iframe 注入
        ("iframe_tag", re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE)),
        # HTML 实体编码绕过
        ("entity_encoded", re.compile(r"&#x?[0-9a-fA-F]+;", re.IGNORECASE)),
        # 常见编码绕过
        ("fromcharcode", re.compile(r"\bString\s*\.\s*fromCharCode\s*\(", re.IGNORECASE)),
        ("atob_btoa", re.compile(r"\batob\s*\(|\bbtoa\s*\(", re.IGNORECASE)),
        # 表达式注入
        ("expression_css", re.compile(r"\bexpression\s*\([^)]*\)", re.IGNORECASE)),
        # data URI 绕过
        ("data_uri_html", re.compile(r"data\s*:\s*text/html", re.IGNORECASE)),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol != "HTTP":
            return []

        candidates = [part for part in (packet.http_path, packet.http_host, packet.raw_summary) if part]

        if not candidates:
            return []

        matched = self._match(candidates)
        if not matched:
            return []

        first_match = matched[0]
        evidence = (
            f"pattern={first_match}; "
            f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"http_host={packet.http_host}; http_path={packet.http_path}"
        )
        return [
            self.create_alert(
                packet,
                alert_type="XSS",
                description=f"检测到 XSS 攻击特征：{first_match}。",
                evidence=evidence,
            )
        ]

    def _match(self, candidates: list[str]) -> list[str]:
        found: list[str] = []
        for text in candidates:
            for name, pattern in self._PATTERNS:
                if pattern.search(text):
                    found.append(name)
        return found