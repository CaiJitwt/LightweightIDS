from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import re

from models import AlertRecord, RuleRecord, SecurityEventRecord


HOST_EVENT_RULE_IDS = {
    "WINDOWS_LOGON_FAILURE",
    "WINDOWS_PERSISTENCE",
    "WINDOWS_PRIVILEGE_CHANGE",
    "POWERSHELL_SUSPICIOUS",
    "SECURITY_CONTROL_TAMPER",
    "RDP_LATERAL_ACTIVITY",
}

POWERSHELL_INDICATORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("encoded-command", re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\b")),
    ("base64-decode", re.compile(r"(?i)frombase64string\s*\(")),
    ("download-cradle", re.compile(r"(?i)(?:downloadstring|invoke-webrequest|start-bitstransfer)")),
    ("expression-execution", re.compile(r"(?i)(?:invoke-expression|\biex\b)")),
    ("policy-bypass", re.compile(r"(?i)-(?:executionpolicy|ep)\s+bypass\b")),
    ("credential-tooling", re.compile(r"(?i)(?:invoke-mimikatz|sekurlsa::|lsadump::)")),
)


class SecurityEventAnalyzer:
    def __init__(self, rules: list[RuleRecord] | None = None) -> None:
        self._rules: dict[str, RuleRecord] = {}
        self._windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.update_rules(rules or [])

    def update_rules(self, rules: list[RuleRecord]) -> None:
        self._rules = {rule.id: rule for rule in rules if rule.id in HOST_EVENT_RULE_IDS}

    def process(self, event: SecurityEventRecord) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        if event.event_id == 4625:
            alert = self._counted_alert(
                "WINDOWS_LOGON_FAILURE",
                event,
                event.source_ip or event.user or event.computer or "local",
                "Repeated Windows authentication failures were observed.",
            )
            if alert:
                alerts.append(alert)

        if event.event_id in {4697, 4698, 4702, 7045}:
            alert = self._immediate_alert(
                "WINDOWS_PERSISTENCE",
                event,
                "A Windows service or scheduled task was created or modified.",
            )
            if alert:
                alerts.append(alert)

        if event.event_id in {4720, 4728, 4732}:
            alert = self._immediate_alert(
                "WINDOWS_PRIVILEGE_CHANGE",
                event,
                "A Windows account or privileged group membership changed.",
            )
            if alert:
                alerts.append(alert)

        if event.event_id in {1102, 5001}:
            alert = self._immediate_alert(
                "SECURITY_CONTROL_TAMPER",
                event,
                "A Windows security control was disabled or an audit log was cleared.",
            )
            if alert:
                alerts.append(alert)

        if event.event_id in {4103, 4104}:
            rule = self._enabled_rule("POWERSHELL_SUSPICIOUS")
            if rule:
                inspected = f"{event.command_line} {event.summary}"
                indicators = [name for name, pattern in POWERSHELL_INDICATORS if pattern.search(inspected)]
                if len(indicators) >= rule.threshold:
                    alerts.append(
                        self._create_alert(
                            rule,
                            event,
                            "PowerShell operational logging contains multiple suspicious execution indicators.",
                            extra=f"indicators={indicators}",
                        )
                    )

        remote_interactive = event.event_id == 4624 and event.logon_type == "10"
        terminal_session = "TerminalServices" in event.channel and event.event_id in {21, 25}
        if remote_interactive or terminal_session:
            alert = self._counted_alert(
                "RDP_LATERAL_ACTIVITY",
                event,
                event.source_ip or event.user or event.computer or "remote-session",
                "Repeated remote interactive Windows logons were observed.",
            )
            if alert:
                alerts.append(alert)
        return alerts

    def reset(self) -> None:
        self._windows.clear()

    def _enabled_rule(self, rule_id: str) -> RuleRecord | None:
        rule = self._rules.get(rule_id)
        return rule if rule and rule.enabled else None

    def _immediate_alert(self, rule_id: str, event: SecurityEventRecord, description: str) -> AlertRecord | None:
        rule = self._enabled_rule(rule_id)
        if rule is None:
            return None
        return self._create_alert(rule, event, description)

    def _counted_alert(
        self,
        rule_id: str,
        event: SecurityEventRecord,
        key: str,
        description: str,
    ) -> AlertRecord | None:
        rule = self._enabled_rule(rule_id)
        if rule is None:
            return None
        now = _event_time(event.timestamp)
        window = max(1, rule.time_window)
        hits = self._windows[(rule_id, key)]
        hits.append(now)
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) < max(1, rule.threshold):
            return None
        count = len(hits)
        hits.clear()
        return self._create_alert(rule, event, description, extra=f"event_count={count}; time_window={window}s")

    def _create_alert(
        self,
        rule: RuleRecord,
        event: SecurityEventRecord,
        description: str,
        extra: str = "",
    ) -> AlertRecord:
        evidence_parts = [
            f"event_id={event.event_id}",
            f"record_id={event.record_id}",
            f"channel={event.channel}",
            f"computer={event.computer or 'unknown'}",
            f"user={event.user or 'unknown'}",
        ]
        if event.source_ip:
            evidence_parts.append(f"source_ip={event.source_ip}")
        if event.logon_type:
            evidence_parts.append(f"logon_type={event.logon_type}")
        if event.process_name:
            evidence_parts.append(f"process={event.process_name}")
        if extra:
            evidence_parts.append(extra)
        return AlertRecord(
            timestamp=event.timestamp,
            rule_id=rule.id,
            rule_name=rule.name,
            alert_type=rule.id,
            severity=rule.severity,
            src_ip=event.source_ip or None,
            protocol="WINDOWS_EVENT",
            description=description,
            evidence="; ".join(evidence_parts),
        )


def _event_time(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()
