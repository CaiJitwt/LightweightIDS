from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class BaselineRecord:
    id: Optional[int] = None
    src_ip: str = ""
    updated_at: str = ""
    window_seconds: int = 60
    packet_count: int = 0
    connection_count: int = 0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    avg_packet_length: float = 0.0
    bytes_per_window: int = 0
    internal_to_external_ratio: float = 0.0
