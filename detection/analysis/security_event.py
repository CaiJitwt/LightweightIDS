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

POWERSHELL_INDICATORS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("encoded-command", 2, re.compile(r"(?i)(?:^|\s)-(?:e(?:nc(?:odedcommand)?)?)\b")),
    ("base64-decode", 2, re.compile(r"(?i)frombase64string\s*\(")),
    ("download-cradle", 2, re.compile(r"(?i)(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer)")),
    ("expression-execution", 2, re.compile(r"(?i)(?:invoke-expression|\biex\b)")),
    ("policy-bypass", 1, re.compile(r"(?i)-(?:executionpolicy|ep)\s+bypass\b")),
    ("hidden-window", 1, re.compile(r"(?i)-(?:windowstyle|w)\s+hidden\b")),
    ("credential-tooling", 5, re.compile(r"(?i)(?:invoke-mimikatz|sekurlsa::|lsadump::|comsvcs\.dll.*minidump)")),
    ("amsi-bypass", 5, re.compile(r"(?i)(?:amsiutils|amsiinitfailed|amsiscanbuffer)")),
    (
        "defender-disable",
        5,
        re.compile(
            r"(?i)(?:set-mppreference\b.*-disablerealtimemonitoring\s+\$?true|"
            r"add-mppreference\b.*-exclusion(?:path|process|extension))"
        ),
    ),
    (
        "script-logging-disable",
        5,
        re.compile(
            r"(?i)(?:set-itemproperty|new-itemproperty|reg(?:\.exe)?\s+add).{0,160}"
            r"(?:scriptblocklogging|modulelogging).{0,80}(?:\b0\b|disabled)"
        ),
    ),
)

POWERSHELL_SEVERE_INDICATORS = {
    "credential-tooling",
    "amsi-bypass",
    "defender-disable",
    "script-logging-disable",
}

PERSISTENCE_INDICATORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("script-interpreter", re.compile(r"(?i)\b(?:powershell|pwsh|cmd|wscript|cscript|mshta)(?:\.exe)?\b")),
    ("proxy-execution", re.compile(r"(?i)\b(?:rundll32|regsvr32|certutil)(?:\.exe)?\b")),
    ("encoded-command", re.compile(r"(?i)(?:^|\s)-(?:e(?:nc(?:odedcommand)?)?)\b")),
    ("user-writable-path", re.compile(r"(?i)\\(?:users\\[^\\]+\\appdata|temp|public|downloads)\\|%temp%|%appdata%")),
    ("network-path", re.compile(r"\\\\[^\\\s]+\\[^\\\s]+")),
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
            inspected = self._event_text(event)
            indicators = [name for name, pattern in PERSISTENCE_INDICATORS if pattern.search(inspected)]
            if indicators:
                alert = self._immediate_alert(
                    "WINDOWS_PERSISTENCE",
                    event,
                    "A Windows service or scheduled task change contains high-risk execution indicators.",
                    extra=f"indicators={indicators}",
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
                inspected = self._event_text(event)
                matched = [(name, weight) for name, weight, pattern in POWERSHELL_INDICATORS if pattern.search(inspected)]
                indicators = [name for name, _weight in matched]
                risk_score = sum(weight for _name, weight in matched)
                if self._is_high_risk_powershell(indicators, risk_score, rule.threshold):
                    alerts.append(
                        self._create_alert(
                            rule,
                            event,
                            "PowerShell operational logging contains a high-risk command or execution chain.",
                            extra=f"risk_score={risk_score}; indicators={indicators}",
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

    def _immediate_alert(
        self,
        rule_id: str,
        event: SecurityEventRecord,
        description: str,
        extra: str = "",
    ) -> AlertRecord | None:
        rule = self._enabled_rule(rule_id)
        if rule is None:
            return None
        return self._create_alert(rule, event, description, extra=extra)

    @staticmethod
    def _event_text(event: SecurityEventRecord) -> str:
        details = " ".join(f"{key}={value}" for key, value in event.details.items())
        return f"{event.command_line} {event.process_name} {event.summary} {details}"

    @staticmethod
    def _is_high_risk_powershell(indicators: list[str], risk_score: int, threshold: int) -> bool:
        matched = set(indicators)
        if matched & POWERSHELL_SEVERE_INDICATORS:
            return True
        if risk_score < max(1, threshold):
            return False
        download_and_execute = {"download-cradle", "expression-execution"} <= matched
        encoded_payload_chain = "encoded-command" in matched and bool(
            matched & {"download-cradle", "expression-execution", "base64-decode"}
        )
        return download_and_execute or encoded_payload_chain

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
