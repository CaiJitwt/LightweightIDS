from __future__ import annotations

import re

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class WebAttackRule(RuleBase):
    rule_id = "WEB_ATTACK"
    name = "Web 攻击检测"
    category = "web"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    _PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # ---- 目录遍历 ----
        ("path_traversal_dot", re.compile(r"\.\./|\.\.\\")),
        ("path_traversal_etc", re.compile(r"/etc/(passwd|shadow|hosts|group)")),
        ("path_traversal_win", re.compile(r"windows\\win\.ini|winnt\\win\.ini|boot\.ini")),
        ("path_traversal_proc", re.compile(r"/proc/self/(environ|cmdline)")),
        # ---- 命令注入 ----
        ("cmd_inject_semicolon", re.compile(r";\s*(id|ls|cat |whoami|pwd|uname|dir |type )", re.IGNORECASE)),
        ("cmd_inject_pipe", re.compile(r"\|\s*(id|ls|cat |whoami|pwd|uname|dir |type )", re.IGNORECASE)),
        ("cmd_inject_and", re.compile(r"&&\s*(id|ls|cat |whoami|pwd|dir )", re.IGNORECASE)),
        ("cmd_inject_backtick", re.compile(r"`[^`]+`")),
        ("cmd_inject_subshell", re.compile(r"\$\([^)]+\)")),
        ("cmd_inject_powershell", re.compile(r"\bpowershell\b.*-enc\b|\bpowershell\b.*-command\b", re.IGNORECASE)),
        ("cmd_inject_cmd", re.compile(r"\bcmd\s*\.exe\s*/c\b|\bcmd\s*/c\b", re.IGNORECASE)),
        ("cmd_inject_bash", re.compile(r"\b/bin/bash\b|\b/bin/sh\b|\bbash\s+-c\b|\bsh\s+-c\b")),
        # ---- 文件包含 ----
        ("file_inclusion_php", re.compile(r"php://(filter|input|fd|memory|temp)", re.IGNORECASE)),
        ("file_inclusion_file", re.compile(r"file:///", re.IGNORECASE)),
        ("file_inclusion_expect", re.compile(r"expect://", re.IGNORECASE)),
        ("file_inclusion_data", re.compile(r"data://text/plain", re.IGNORECASE)),
        # ---- SSRF ----
        ("ssrf_aws_metadata", re.compile(r"169\.254\.169\.254")),
        ("ssrf_localhost", re.compile(r"https?://localhost[/:]", re.IGNORECASE)),
        ("ssrf_loopback", re.compile(r"https?://127\.0\.0\.1[/:]|\b127\.0\.0\.1\b")),
        ("ssrf_internal_net", re.compile(r"https?://(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)")),
        ("ssrf_ipv6_loopback", re.compile(r"https?://\[::1\]")),
        # ---- 反序列化 ----
        ("deser_java", re.compile(r"\bjava\.lang\.Runtime\b|\bjava\.util\.ProcessBuilder\b|\bjava\.net\.URL\b")),
        ("deser_php", re.compile(r"\bO:\d+:")),
        ("deser_ysoserial", re.compile(r"\bysoserial\b|\bCommonsCollections\b|\bJdk7u21\b|\bJdk8u20\b", re.IGNORECASE)),
        # ---- XXE ----
        ("xxe_entity", re.compile(r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)", re.IGNORECASE)),
        ("xxe_doctype", re.compile(r"<!DOCTYPE\s+\w+\s+\[", re.IGNORECASE)),
        # ---- SSTI (模板注入) ----
        ("ssti_jinja", re.compile(r"\{\{.*\}\}|\{%\s*(if|for|block|extends|include|set)")),
        ("ssti_freemarker", re.compile(r"\$\{.*\}|\<#(if|list|assign|include)")),
        # ---- CRLF 注入 ----
        ("crlf", re.compile(r"%0d%0a|\r\n.*(Content-Length|Set-Cookie|Location):", re.IGNORECASE)),
        # ---- LDAP 注入 ----
        ("ldap_inject", re.compile(r"\*\s*\(\s*\||\*\s*\(\s*&|\(\s*objectClass\s*=", re.IGNORECASE)),
        # ---- XPath 注入 ----
        ("xpath_inject", re.compile(r"' or '1'='1|\" or \"1\"=\"1|' or 1=1", re.IGNORECASE)),
        # ---- 缓冲区溢出 ----
        ("buffer_overflow", re.compile(r"A{100,}|%x{20,}|%n{10,}")),
        # ---- 代理探测 ----
        ("proxy_probe", re.compile(r"X-Forwarded-For:\s*127\.0\.0\.1|X-Real-IP:\s*127\.0\.0\.1", re.IGNORECASE)),
        # ---- 敏感文件探测 ----
        ("sensitive_file", re.compile(r"\.(git|svn|env|htaccess|DS_Store|wp-config|config\.php|\.ssh|\.aws|\.dockercfg)", re.IGNORECASE)),
        # ---- webshell ----
        ("webshell_eval", re.compile(r"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)", re.IGNORECASE)),
        ("webshell_china_chopper", re.compile(r"@eval\s*\(\s*base64_decode\s*\(|@assert\s*\(\s*base64_decode\s*\(", re.IGNORECASE)),
        ("webshell_godzilla", re.compile(r"\bClassLoader\b.*\bdefineClass\b|\bgetSystemClassLoader\b", re.IGNORECASE)),
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
                alert_type="WEB_ATTACK",
                description=f"检测到 Web 攻击特征：{first_match}。",
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