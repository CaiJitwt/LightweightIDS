from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
import time
from typing import Optional

from models import AlertRecord, PacketRecord


class RuleBase(ABC):
    rule_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "LOW"
    enabled: bool = True
    threshold: int = 1
    time_window: int = 0

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        threshold: int | None = None,
        time_window: int | None = None,
        severity: str | None = None,
    ) -> None:
        if enabled is not None:
            self.enabled = enabled
        if threshold is not None:
            self.threshold = threshold
        if time_window is not None:
            self.time_window = time_window
        if severity is not None:
            self.severity = severity.upper()

    @abstractmethod
    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        raise NotImplementedError

    def reset(self) -> None:
        return None

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled

    def set_threshold(self, threshold: int) -> None:
        self.threshold = threshold

    def set_time_window(self, time_window: int) -> None:
        self.time_window = time_window

    def packet_time(self, packet: PacketRecord) -> float:
        if not packet.timestamp:
            return time.time()

        timestamp = packet.timestamp.strip()
        for parser in (
            datetime.fromisoformat,
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f"),
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        ):
            try:
                return parser(timestamp).timestamp()
            except ValueError:
                continue
        return time.time()

    def create_alert(
        self,
        packet: PacketRecord,
        *,
        alert_type: str,
        description: str,
        evidence: str,
        severity: Optional[str] = None,
    ) -> AlertRecord:
        return AlertRecord(
            timestamp=packet.timestamp,
            rule_id=self.rule_id,
            rule_name=self.name,
            alert_type=alert_type,
            severity=(severity or self.severity).upper(),
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            description=description,
            evidence=evidence,
        )
