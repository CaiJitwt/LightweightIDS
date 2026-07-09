from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models import AlertRecord


@dataclass(frozen=True)
class AttackChain:
    source_ip: str
    stages: list[str]
    alerts: list[AlertRecord]
    risk_score: int

    @property
    def summary(self) -> str:
        return " -> ".join(self.stages)


class AttackChainAnalyzer:
    STAGE_BY_RULE = {
        "PORT_SCAN": "scan",
        "HOST_SCAN": "scan",
        "SENSITIVE_PORT": "scan",
        "SQL_INJECTION": "exploit",
        "XSS": "exploit",
        "HTTP_SUSPICIOUS": "exploit",
        "WEB_ATTACK": "exploit",
        "MALICIOUS_COMMAND": "execution",
        "BRUTE_FORCE": "credential_access",
        "DNS_ANOMALY": "c2",
        "ABNORMAL_OUTBOUND": "c2",
        "TLS_FINGERPRINT": "c2",
        "LATERAL_MOVEMENT": "lateral_movement",
    }
    STAGE_BY_TYPE = {
        "C2_HEARTBEAT_SUSPECTED": "c2",
        "NON_STANDARD_OUTBOUND": "c2",
        "ADMIN_SHARE_ACCESS": "lateral_movement",
        "LATERAL_MOVEMENT": "lateral_movement",
        "TLS_WEAK_FINGERPRINT": "c2",
        "ML_ANOMALY": "anomaly",
    }

    def analyze(self, alerts: list[AlertRecord]) -> list[AttackChain]:
        grouped: dict[str, list[AlertRecord]] = {}
        for alert in alerts:
            if not alert.src_ip:
                continue
            grouped.setdefault(alert.src_ip, []).append(alert)

        chains: list[AttackChain] = []
        for source_ip, source_alerts in grouped.items():
            ordered_alerts = sorted(source_alerts, key=self._timestamp_key)
            stages = self._ordered_stages(ordered_alerts)
            if len(stages) < 2:
                continue
            chains.append(
                AttackChain(
                    source_ip=source_ip,
                    stages=stages,
                    alerts=ordered_alerts,
                    risk_score=self._risk_score(stages, ordered_alerts),
                )
            )

        return sorted(chains, key=lambda chain: chain.risk_score, reverse=True)

    def stage_distribution(self, alerts: list[AlertRecord]) -> dict[str, int]:
        distribution: dict[str, int] = {}
        for alert in alerts:
            stage = self._stage_for(alert)
            if stage:
                distribution[stage] = distribution.get(stage, 0) + 1
        return distribution

    def _ordered_stages(self, alerts: list[AlertRecord]) -> list[str]:
        stages: list[str] = []
        for alert in alerts:
            stage = self._stage_for(alert)
            if stage and stage not in stages:
                stages.append(stage)
        return stages

    def _stage_for(self, alert: AlertRecord) -> str | None:
        return self.STAGE_BY_TYPE.get(alert.alert_type) or self.STAGE_BY_RULE.get(alert.rule_id)

    def _risk_score(self, stages: list[str], alerts: list[AlertRecord]) -> int:
        score = len(stages) * 18
        score += sum(10 for alert in alerts if alert.severity == "CRITICAL")
        score += sum(5 for alert in alerts if alert.severity == "HIGH")
        return min(score, 100)

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
