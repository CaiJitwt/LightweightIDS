from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import ClassVar, Optional


@dataclass(slots=True)
class InvestigationRecord:
    VALID_STATUSES: ClassVar[set[str]] = {"Open", "Monitoring", "Closed"}
    VALID_PRIORITIES: ClassVar[set[str]] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    id: Optional[int] = None
    title: str = ""
    status: str = "Open"
    priority: str = "MEDIUM"
    host_ip: Optional[str] = None
    summary: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.title = self.title.strip()
        if not self.title:
            raise ValueError("Investigation title is required")
        self.status = self.status.title()
        self.priority = self.priority.upper()
        if self.status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid investigation status: {self.status}")
        if self.priority not in self.VALID_PRIORITIES:
            raise ValueError(f"Invalid investigation priority: {self.priority}")
        if self.host_ip:
            self.host_ip = str(ip_address(self.host_ip.strip()))


@dataclass(slots=True)
class InvestigationEvidenceRecord:
    id: Optional[int] = None
    investigation_id: int = 0
    alert_id: Optional[int] = None
    alert_timestamp: str = ""
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "LOW"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    description: str = ""
    evidence: str = ""
    added_at: str = ""

