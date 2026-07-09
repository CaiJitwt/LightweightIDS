from __future__ import annotations

from models import AlertRecord, CustomRuleRecord, PacketRecord
from models import RuleRecord
from detection.analysis.false_positive import AlertNoiseReducer
from detection.rule_base import RuleBase
from detection.rules.abnormal_outbound import AbnormalOutboundRule
from detection.rules.bandwidth_spike import BandwidthSpikeRule
from detection.rules.baseline_deviation import BaselineDeviationRule
from detection.rules.blacklist import BlacklistRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.custom_rule import CustomRule
from detection.rules.dns_anomaly import DnsAnomalyRule
from detection.rules.host_scan import HostScanRule
from detection.rules.http_suspicious import HttpSuspiciousRule
from detection.rules.icmp_flood import IcmpFloodRule
from detection.rules.lateral_movement import LateralMovementRule
from detection.rules.malicious_command import MaliciousCommandRule
from detection.rules.ml_anomaly import MlAnomalyRule
from detection.rules.ml_flow_anomaly import MlFlowAnomalyRule
from detection.rules.port_scan import PortScanRule
from detection.rules.sensitive_port import SensitivePortRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.signature_rule import SignatureRule
from detection.rules.syn_flood import SynFloodRule
from detection.rules.session_duration_anomaly import SessionDurationAnomalyRule
from detection.rules.tls_fingerprint import TlsFingerprintRule
from detection.rules.web_attack import WebAttackRule
from detection.rules.xss import XssRule


class DetectionEngine:
    def __init__(
        self,
        rules: list[RuleBase] | None = None,
        alert_cooldown_seconds: int = 10,
        *,
        whitelist_ips: set[str] | None = None,
        asset_importance: dict[str, int] | None = None,
        minimum_severity: str = "LOW",
    ) -> None:
        self.rules = rules or []
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.noise_reducer = AlertNoiseReducer(
            whitelist_ips=whitelist_ips,
            asset_importance=asset_importance,
            minimum_severity=minimum_severity,
        )
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
                BruteForceRule(),
                DnsAnomalyRule(),
                HttpSuspiciousRule(),
                SqlInjectionRule(),
                XssRule(),
                MaliciousCommandRule(),
                AbnormalOutboundRule(),
                LateralMovementRule(),
                HostScanRule(),
                TlsFingerprintRule(),
                MlAnomalyRule(),
                WebAttackRule(),
                MlFlowAnomalyRule(),
                SignatureRule(),
                BaselineDeviationRule(),
                BandwidthSpikeRule(),
                SessionDurationAnomalyRule(),
            ],
            alert_cooldown_seconds=alert_cooldown_seconds,
        )

    @classmethod
    def from_rule_records(
        cls,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord] | None = None,
        alert_cooldown_seconds: int = 10,
    ) -> "DetectionEngine":
        rule_map = {
            "PORT_SCAN": PortScanRule,
            "SYN_FLOOD": SynFloodRule,
            "ICMP_FLOOD": IcmpFloodRule,
            "SENSITIVE_PORT": SensitivePortRule,
            "BLACKLIST_IP": BlacklistRule,
            "BRUTE_FORCE": BruteForceRule,
            "DNS_ANOMALY": DnsAnomalyRule,
            "HTTP_SUSPICIOUS": HttpSuspiciousRule,
            "SQL_INJECTION": SqlInjectionRule,
            "XSS": XssRule,
            "MALICIOUS_COMMAND": MaliciousCommandRule,
            "ABNORMAL_OUTBOUND": AbnormalOutboundRule,
            "LATERAL_MOVEMENT": LateralMovementRule,
            "HOST_SCAN": HostScanRule,
            "TLS_FINGERPRINT": TlsFingerprintRule,
            "ML_ANOMALY": MlAnomalyRule,
            "WEB_ATTACK": WebAttackRule,
            "ML_FLOW_ANOMALY": MlFlowAnomalyRule,
            "SIGNATURE_MATCH": SignatureRule,
            "BASELINE_DEVIATION": BaselineDeviationRule,
            "BANDWIDTH_SPIKE": BandwidthSpikeRule,
            "SESSION_DURATION_ANOMALY": SessionDurationAnomalyRule,
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
        for record in custom_rule_records or []:
            if record.enabled:
                rules.append(CustomRule(record))
        return cls(rules=rules, alert_cooldown_seconds=alert_cooldown_seconds)

    def add_rule(self, rule: RuleBase) -> None:
        self.rules.append(rule)

    def process_packet(self, packet: PacketRecord) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            for alert in rule.process(packet):
                if self.noise_reducer.is_whitelisted(alert):
                    continue
                alert = self.noise_reducer.apply_asset_importance(alert)
                if not self.noise_reducer.meets_minimum_severity(alert):
                    continue
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
