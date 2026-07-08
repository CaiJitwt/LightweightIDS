from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class CustomRuleRecord:
    id: Optional[int] = None
    name: str = ""
    severity: str = "LOW"
    enabled: bool = True
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    keyword: Optional[str] = None
    description: str = ""
