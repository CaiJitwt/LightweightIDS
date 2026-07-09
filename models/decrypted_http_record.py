from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class DecryptedHttpRecord:
    timestamp: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    method: str = ""
    host: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    source: str = ""
