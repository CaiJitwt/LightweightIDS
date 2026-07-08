from __future__ import annotations

from models import AlertRecord, PacketRecord
from models import RuleRecord
from detection.rule_base import RuleBase
from detection.rules.blacklist import BlacklistRule
from detection.rules.icmp_flood import IcmpFloodRule
from detection.rules.port_scan import PortScanRule
from detection.rules.sensitive_port import SensitivePortRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.syn_flood import SynFloodRule
from detection.rules.xss import XssRule


class DetectionEngine:
    def __init__(self, rules: list[RuleBase] | None = None, alert_cooldown_seconds: int = 10) -> None:
        self.rules = rules or []
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self._last_alert_at: dict[tuple[str, str | None, str | None], float] = {}

    @classmethod
    def with_default_rules(cls, alert_cooldown_seconds: int = 10) -> "DetectionEngine":
        return cls(
            rules=[
                PortScanRule(),
                SynFloodRule(),
                IcmpFloodRule(),
                SensitivePortRule(),
                BlacklistRule(),
                SqlInjectionRule(),
                XssRule(),
            ],
            alert_cooldown_seconds=alert_cooldown_seconds,
        )

    @classmethod
    def from_rule_records(cls, rule_records: list[RuleRecord], alert_cooldown_seconds: int = 10) -> "DetectionEngine":
        rule_map = {
            "PORT_SCAN": PortScanRule,
            "SYN_FLOOD": SynFloodRule,
            "ICMP_FLOOD": IcmpFloodRule,
            "SENSITIVE_PORT": SensitivePortRule,
            "BLACKLIST_IP": BlacklistRule,
            "SQL_INJECTION": SqlInjectionRule,
            "XSS": XssRule,
        }
        rules: list[RuleBase] = []
        for record in rule_records:
            rule_class = rule_map.get(record.id)
            if rule_class is None:
                continue
            rules.append(
                rule_class(
                    enabled=record.enabled,
                    threshold=record.threshold,
                    time_window=record.time_window,
                    severity=record.severity,
                )
            )
        return cls(rules=rules, alert_cooldown_seconds=alert_cooldown_seconds)

    def add_rule(self, rule: RuleBase) -> None:
        self.rules.append(rule)

    def process_packet(self, packet: PacketRecord) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            for alert in rule.process(packet):
                if self._is_allowed_by_cooldown(rule, packet, alert):
                    alerts.append(alert)
        return alerts

    def process_packets(self, packets: list[PacketRecord]) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        for packet in packets:
            alerts.extend(self.process_packet(packet))
        return alerts

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        rule = self.get_rule(rule_id)
        if rule:
            rule.set_enabled(enabled)

    def update_rule_threshold(self, rule_id: str, threshold: int) -> None:
        rule = self.get_rule(rule_id)
        if rule:
            rule.set_threshold(threshold)

    def update_rule_time_window(self, rule_id: str, time_window: int) -> None:
        rule = self.get_rule(rule_id)
        if rule:
            rule.set_time_window(time_window)

    def get_rule(self, rule_id: str) -> RuleBase | None:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def reset(self) -> None:
        self._last_alert_at.clear()
        for rule in self.rules:
            rule.reset()

    def _is_allowed_by_cooldown(self, rule: RuleBase, packet: PacketRecord, alert: AlertRecord) -> bool:
        if self.alert_cooldown_seconds <= 0:
            return True

        alert_key = (alert.rule_id, alert.src_ip, alert.dst_ip)
        now = rule.packet_time(packet)
        previous = self._last_alert_at.get(alert_key)
        if previous is not None and now - previous < self.alert_cooldown_seconds:
            return False

        self._last_alert_at[alert_key] = now
        return True
