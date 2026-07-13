from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class HostSummary:
    ip: str
    display_name: str = ""
    role: str = "Other"
    importance: int = 0
    risk_score: int = 0
    packet_count: int = 0
    alert_count: int = 0
    critical_count: int = 0
    incoming_packets: int = 0
    outgoing_packets: int = 0
    last_seen: str = ""
    risk_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HostConnectionSummary:
    peer_ip: str
    direction: str
    protocol: str
    port: Optional[int]
    packet_count: int
    last_seen: str


@dataclass(slots=True)
class HostTimelineEvent:
    timestamp: str
    event_type: str
    direction: str
    peer_ip: str
    summary: str
    severity: str = ""

