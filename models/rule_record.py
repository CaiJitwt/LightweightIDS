from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RuleRecord:
    id: str
    name: str
    category: str
    severity: str
    enabled: bool
    threshold: int
    time_window: int
    description: str
