from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import ClassVar


@dataclass(slots=True)
class AssetRecord:
    VALID_ROLES: ClassVar[set[str]] = {
        "Workstation",
        "Server",
        "Database",
        "Gateway",
        "Domain Controller",
        "Other",
    }

    ip: str = ""
    display_name: str = ""
    role: str = "Other"
    importance: int = 50
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.ip = str(ip_address(self.ip.strip()))
        if self.role not in self.VALID_ROLES:
            raise ValueError(f"Invalid asset role: {self.role}")
        self.importance = int(self.importance)
        if not 0 <= self.importance <= 100:
            raise ValueError("Asset importance must be between 0 and 100")

