from __future__ import annotations

import re

from detection.rule_base import RuleBase
from detection.rules.payload_utils import has_inspectable_payload, packet_text
from models import AlertRecord, PacketRecord


class WebAttackRule(RuleBase):
    rule_id = "WEB_ATTACK"
    name = "Web attack detection (advanced)"
    category = "web"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("path_traversal_dot", re.compile(r"\.\./|\.\.\\")),
        ("path_traversal_etc", re.compile(r"/etc/(passwd|shadow|hosts|group)")),
        ("path_traversal_proc", re.compile(r"/proc/self/(environ|cmdline|fd)")),
        ("win_system_files", re.compile(r"windows\\win\.ini|winnt\\win\.ini|boot\.ini", re.IGNORECASE)),
        ("cmd_inject_semicolon", re.compile(r";\s*(id|ls|cat |whoami|pwd|uname|dir |type )", re.IGNORECASE)),
        ("cmd_inject_pipe", re.compile(r"\|\s*(id|ls|cat |whoami|pwd|uname|dir |type )", re.IGNORECASE)),
        ("cmd_inject_and", re.compile(r"&&\s*(id|ls|cat |whoami|pwd|dir )", re.IGNORECASE)),
        ("cmd_inject_backtick", re.compile(r"`[^`]*(?:\b(?:id|ls|whoami|uname|pwd|netstat)\b|\bcat\b|\bdir\b|\bping\b|\bwget\b|\bcurl\b|\bnc\b|\brm\b|\bchmod\b|\bnmap\b|/etc/passwd)[^`]*`", re.IGNORECASE)),
        ("cmd_inject_subshell", re.compile(r"\$\((?:id|ls|cat |whoami|dir |ping |wget |curl |nc )")),
        ("cmd_inject_powershell", re.compile(r"\bpowershell\b.*-enc\b|\bpowershell\b.*-command\b", re.IGNORECASE)),
        ("cmd_inject_cmd", re.compile(r"\bcmd\s*\.exe\s*/c\b|\bcmd\s*/c\b", re.IGNORECASE)),
        ("cmd_inject_bash", re.compile(r"\b/bin/bash\b|\b/bin/sh\b|\bbash\s+-c\b|\bsh\s+-c\b", re.IGNORECASE)),
        ("file_inclusion_php", re.compile(r"php://(filter|input|fd|memory|temp)", re.IGNORECASE)),
        ("file_inclusion_file", re.compile(r"file:///", re.IGNORECASE)),
        ("file_inclusion_expect", re.compile(r"expect://", re.IGNORECASE)),
        ("file_inclusion_data", re.compile(r"data://text/plain", re.IGNORECASE)),
        ("ssrf_aws_metadata", re.compile(r"169\.254\.169\.254")),
        ("ssrf_localhost", re.compile(r"https?://localhost[/:]", re.IGNORECASE)),
        ("ssrf_loopback", re.compile(r"https?://127\.0\.0\.1[/:]|\b127\.0\.0\.1\b")),
        ("ssrf_internal_net", re.compile(r"https?://(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)")),
        ("ssrf_ipv6_loopback", re.compile(r"https?://\[::1\]")),
        ("xxe_entity", re.compile(r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)", re.IGNORECASE)),
        ("xxe_doctype", re.compile(r"<!DOCTYPE\s+\w+\s+\[", re.IGNORECASE)),
        ("ssti_jinja", re.compile(r"\{\{.*?(?:__class__|__bases__|__mro__|__subclasses__|config\.|self\._|request\.|session\[|\d+\s*[\*\+\-\/]\s*\d+).*?\}\}|\{%\s*(?:if|for|block|extends|include|set)\s")),
        ("ssti_freemarker", re.compile(r"\$\{(?:runtime|class|system|exec|\.getClass|\.getRuntime)\b|<#(?:if|list|assign|include)\s+\w+\.(?:class|get)")),
        ("ssti_velocity", re.compile(r"#set\s*\(\s*\$\w+\.(?:class|forName|getRuntime)")),
        ("crlf", re.compile(r"%0d%0a|\r\n.*(Content-Length|Set-Cookie|Location):", re.IGNORECASE)),
        ("ldap_inject", re.compile(r"\*\s*\(\s*\||\*\s*\(\s*&|\(\s*objectClass\s*=", re.IGNORECASE)),
                ("deser_java", re.compile(r"(?:Runtime\.getRuntime\(\)|ProcessBuilder\(|\.exec\(|sun\.misc\.Unsafe|java\.lang\.reflect)")),
        ("deser_php", re.compile(r"\bO:\d+:")),
        ("deser_ysoserial", re.compile(r"\bysoserial\b|\bCommonsCollections\b|\bJdk7u21\b|\bJdk8u20\b", re.IGNORECASE)),
        ("webshell_eval", re.compile(r"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)", re.IGNORECASE)),
        ("webshell_chopper", re.compile(r"@eval\s*\(\s*base64_decode\s*\(|@assert\s*\(\s*base64_decode\s*\(", re.IGNORECASE)),
        ("webshell_godzilla", re.compile(r"\bClassLoader\b.*\bdefineClass\b|\bgetSystemClassLoader\b", re.IGNORECASE)),
        ("buffer_overflow", re.compile(r"((?:%[0-9a-fA-F]{2}){200,}|A{300,}|%x{30,}|%n{20,})")),
        ("sensitive_file", re.compile(r"(?:/\.(?:git|svn|env|ssh|aws|dockercfg)\b|wp-config\.php|\.htaccess|DS_Store|web\.config|\.bash_history)", re.IGNORECASE)),
        ("proxy_probe", re.compile(r"X-Forwarded-For:\s*127\.0\.0\.1|X-Real-IP:\s*127\.0\.0\.1|\bX-Forwarded-Host:\s*localhost", re.IGNORECASE)),
        ("jndi_inject", re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop|http):", re.IGNORECASE)),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol not in {"HTTP", "HTTPS", "TCP"}:
            return []
        if not has_inspectable_payload(packet):
            return []
        if packet.protocol == "TCP" and not (packet.http_method or packet.http_host or packet.http_path):
            return []
        matches = [name for name, pattern in self.REGEX_PATTERNS if pattern.search(text)]
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="WEB_ATTACK",
                description="Detected advanced web attack indicators.",
                evidence=f"matched={matches}; host={packet.http_host or ''}; path={packet.http_path or ''}",
            )
        ]
