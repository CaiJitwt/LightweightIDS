from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class PacketRecord:
    id: Optional[int] = None
    timestamp: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    length: int = 0
    tcp_flags: Optional[str] = None
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    raw_summary: str = ""
    raw_hex: Optional[str] = None
