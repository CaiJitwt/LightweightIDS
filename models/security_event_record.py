from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class SecurityEventRecord:
    id: Optional[int] = None
    timestamp: str = ""
    channel: str = ""
    event_id: int = 0
    record_id: int = 0
    provider: str = ""
    computer: str = ""
    level: str = ""
    user: str = ""
    source_ip: str = ""
    logon_type: str = ""
    process_name: str = ""
    command_line: str = ""
    summary: str = ""
    details: dict[str, str] = field(default_factory=dict)
    severity: str = "INFO"
    alert_id: Optional[int] = None
