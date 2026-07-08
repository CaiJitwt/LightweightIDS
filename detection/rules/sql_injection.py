from __future__ import annotations

import re

from detection.rule_base import RuleBase
from models import AlertRecord, PacketRecord


class SqlInjectionRule(RuleBase):
    rule_id = "SQL_INJECTION"
    name = "SQL 注入检测"
    category = "injection"
    severity = "CRITICAL"
    threshold = 1
    time_window = 0

    # 编译正则模式，匹配 SQL 注入特征
    _PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # 联合查询注入
        ("union_select", re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE)),
        # 永真式绕认证
        ("tautology", re.compile(r"'\s*OR\s+'1'\s*=\s*'1|'\s*OR\s+1\s*=\s*1|'\s*OR\s+'a'\s*=\s*'a", re.IGNORECASE)),
        # 数字型永真
        ("numeric_tautology", re.compile(r"\bOR\s+1\s*=\s*1\b|\bAND\s+1\s*=\s*1\b", re.IGNORECASE)),
        # SQL 注释绕过
        ("sql_comment", re.compile(r"--\s|--$|/\*.*\*/|#\s*$", re.IGNORECASE)),
        # 危险操作
        ("drop_table", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
        ("alter_table", re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE)),
        ("truncate_table", re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE)),
        # 系统存储过程
        ("xp_cmdshell", re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)),
        ("sp_execute", re.compile(r"\bsp_executesql\b|\bEXEC\s*\(|\bEXECUTE\s*\(", re.IGNORECASE)),
        # 信息探测
        ("information_schema", re.compile(r"\bINFORMATION_SCHEMA\b", re.IGNORECASE)),
        # 时间盲注
        ("time_based", re.compile(r"\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY\b", re.IGNORECASE)),
        # 文件操作
        ("file_ops", re.compile(r"\bLOAD_FILE\s*\(|\bINTO\s+(OUTFILE|DUMPFILE)\b|\bOUTFILE\b", re.IGNORECASE)),
        # 报错注入
        ("error_based", re.compile(r"\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\(|\bFLOOR\s*\(\s*RAND\s*\(\s*\)", re.IGNORECASE)),
        # 堆叠查询
        ("stacked_query", re.compile(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)", re.IGNORECASE)),
        # 宽字节注入
        ("wide_byte", re.compile(r"%df%27|%bf%27|%df'|%bf'", re.IGNORECASE)),
        # 十六进制/编码绕过
        ("hex_encode", re.compile(r"0x[0-9a-fA-F]{6,}", re.IGNORECASE)),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        # 只检测 HTTP 协议
        if packet.protocol != "HTTP":
            return []

        # 拼接所有可检测的文本
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
                alert_type="SQL_INJECTION",
                description=f"检测到 SQL 注入攻击特征：{first_match}。",
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