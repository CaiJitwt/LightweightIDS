from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from models import AlertRecord


class AlertNoiseReducer:
    SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(
        self,
        *,
        whitelist_ips: set[str] | None = None,
        asset_importance: dict[str, int] | None = None,
        merge_window_seconds: int = 60,
        minimum_severity: str = "LOW",
    ) -> None:
        self.whitelist_ips = whitelist_ips or set()
        self.asset_importance = asset_importance or {}
        self.merge_window_seconds = merge_window_seconds
        self.minimum_severity = minimum_severity.upper()

    def filter_alerts(self, alerts: list[AlertRecord]) -> list[AlertRecord]:
        kept: list[AlertRecord] = []
        last_seen: dict[tuple[object, ...], float] = {}
        for alert in alerts:
            if self.is_whitelisted(alert):
                continue
            alert = self.apply_asset_importance(alert)
            if not self.meets_minimum_severity(alert):
                continue
            key = (alert.rule_id, alert.alert_type, alert.src_ip, alert.dst_ip, alert.dst_port)
            timestamp = self._timestamp_key(alert)
            previous = last_seen.get(key)
            if previous is not None and timestamp - previous <= self.merge_window_seconds:
                continue
            last_seen[key] = timestamp
            kept.append(alert)
        return kept

    def is_whitelisted(self, alert: AlertRecord) -> bool:
        return bool(
            (alert.src_ip and alert.src_ip in self.whitelist_ips)
            or (alert.dst_ip and alert.dst_ip in self.whitelist_ips)
        )

    def apply_asset_importance(self, alert: AlertRecord) -> AlertRecord:
        importance = max(
            self.asset_importance.get(alert.src_ip or "", 0),
            self.asset_importance.get(alert.dst_ip or "", 0),
        )
        if importance < 80:
            return alert

        severity = alert.severity
        if importance >= 90 and severity == "HIGH":
            severity = "CRITICAL"
        elif severity in {"LOW", "MEDIUM"}:
            severity = "HIGH"

        if severity == alert.severity:
            return alert

        evidence = f"{alert.evidence}; asset_importance={importance}"
        return replace(alert, severity=severity, evidence=evidence)

    def meets_minimum_severity(self, alert: AlertRecord) -> bool:
        minimum_index = self._severity_index(self.minimum_severity)
        alert_index = self._severity_index(alert.severity)
        return alert_index >= minimum_index

    def _severity_index(self, severity: str) -> int:
        try:
            return self.SEVERITY_ORDER.index(severity.upper())
        except ValueError:
            return 0

    def _timestamp_key(self, alert: AlertRecord) -> float:
        if not alert.timestamp:
            return 0.0
        for parser in (
            datetime.fromisoformat,
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f"),
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        ):
            try:
                return parser(alert.timestamp).timestamp()
            except ValueError:
                continue
        return 0.0
