from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class StatisticsRecord:
    packet_count: int = 0
    alert_count: int = 0
    high_severity_count: int = 0
    protocol_distribution: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)
