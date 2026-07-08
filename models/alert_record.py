from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional


@dataclass(slots=True)
class AlertRecord:
    VALID_SEVERITIES: ClassVar[set[str]] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    id: Optional[int] = None
    timestamp: str = ""
    rule_id: str = ""
    rule_name: str = ""
    alert_type: str = ""
    severity: str = "LOW"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ""
    evidence: str = ""
    status: str = "unconfirmed"

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
