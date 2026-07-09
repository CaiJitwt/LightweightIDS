from __future__ import annotations

import re

from detection.rule_base import RuleBase
from detection.rules.payload_utils import packet_text
from models import AlertRecord, PacketRecord


class WebAttackRule(RuleBase):
    rule_id = "WEB_ATTACK"
    name = "Web attack detection (advanced)"
    category = "web"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    # Complements HTTP_SUSPICIOUS with deeper coverage: XXE, SSTI, CRLF injection,
    # LDAP/XPath injection, deserialization (Java/PHP), webshell signatures,
    # buffer overflow probes, and sensitive file discovery.
    REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # ---- XXE (XML External Entity) ----
        ("xxe_entity", re.compile(r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)", re.IGNORECASE)),
        ("xxe_doctype", re.compile(r"<!DOCTYPE\s+\w+\s+\[", re.IGNORECASE)),
        # ---- SSTI (Server-Side Template Injection) ----
        ("ssti_jinja", re.compile(r"\{\{.*\}\}|\{%\s*(if|for|block|extends|include|set)")),
        ("ssti_freemarker", re.compile(r"\$\{.*\}|\<#(if|list|assign|include)")),
        ("ssti_velocity", re.compile(r"#set\s*\(\s*\$\w+")),
        # ---- CRLF injection ----
        ("crlf", re.compile(r"%0d%0a|\r\n.*(Content-Length|Set-Cookie|Location):", re.IGNORECASE)),
        # ---- LDAP injection ----
        ("ldap_inject", re.compile(r"\*\s*\(\s*\||\*\s*\(\s*&|\(\s*objectClass\s*=", re.IGNORECASE)),
        # ---- XPath injection ----
        ("xpath_inject", re.compile(r"' or '1'='1|\" or \"1\"=\"1|' or 1=1", re.IGNORECASE)),
        # ---- Deserialization ----
        ("deser_java", re.compile(r"\bjava\.lang\.Runtime\b|\bjava\.util\.ProcessBuilder\b|\bjava\.net\.URL\b")),
        ("deser_php", re.compile(r"\bO:\d+:")),
        ("deser_ysoserial", re.compile(r"\bysoserial\b|\bCommonsCollections\b|\bJdk7u21\b|\bJdk8u20\b", re.IGNORECASE)),
        # ---- Webshell (PHP) ----
        ("webshell_eval", re.compile(r"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)", re.IGNORECASE)),
        ("webshell_chopper", re.compile(r"@eval\s*\(\s*base64_decode\s*\(|@assert\s*\(\s*base64_decode\s*\(", re.IGNORECASE)),
        ("webshell_godzilla", re.compile(r"\bClassLoader\b.*\bdefineClass\b|\bgetSystemClassLoader\b", re.IGNORECASE)),
        # ---- Buffer overflow probes ----
        ("buffer_overflow", re.compile(r"A{100,}|%x{20,}|%n{10,}")),
        # ---- Sensitive file discovery ----
        ("sensitive_file", re.compile(r"\.(git|svn|env|htaccess|DS_Store|wp-config|config\.php|\.ssh|\.aws|\.dockercfg)", re.IGNORECASE)),
        ("proc_self", re.compile(r"/proc/self/(environ|cmdline|fd)")),
        ("win_system_files", re.compile(r"windows\\win\.ini|winnt\\win\.ini|boot\.ini")),
        # ---- Proxy/header manipulation ----
        ("proxy_probe", re.compile(r"X-Forwarded-For:\s*127\.0\.0\.1|X-Real-IP:\s*127\.0\.0\.1|\bX-Forwarded-Host:\s*localhost", re.IGNORECASE)),
        # ---- Log4Shell / JNDI ----
        ("jndi_inject", re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop|http):", re.IGNORECASE)),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []

        text = packet_text(packet)
        matches = [name for name, pattern in self.REGEX_PATTERNS if pattern.search(text)]
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="WEB_ATTACK",
                description="Detected advanced web attack indicators (XXE, SSTI, deserialization, webshell, etc.).",
                evidence=f"matched={matches}; host={packet.http_host or ''}; path={packet.http_path or ''}",
            )
        ]