from __future__ import annotations

from dataclasses import dataclass

from detection.analysis.attack_chain import AttackChain, AttackChainAnalyzer
from models import AlertRecord, BaselineRecord


@dataclass(frozen=True)
class HostRiskBreakdown:
    source_ip: str
    score: int
    severity_score: int
    chain_score: int
    baseline_score: int
    asset_score: int
    reasons: list[str]


class HostRiskScorer:
    SEVERITY_POINTS = {
        "LOW": 6,
        "MEDIUM": 14,
        "HIGH": 26,
        "CRITICAL": 40,
    }
    BASELINE_DEVIATION_RULES = {"BASELINE_DEVIATION", "BANDWIDTH_SPIKE", "SESSION_DURATION_ANOMALY"}

    def __init__(self, analyzer: AttackChainAnalyzer | None = None) -> None:
        self.analyzer = analyzer or AttackChainAnalyzer()

    def score_hosts(
        self,
        alerts: list[AlertRecord],
        attack_chains: list[AttackChain] | None = None,
        baseline_records: list[BaselineRecord] | None = None,
        asset_importance: dict[str, int] | None = None,
        limit: int | None = None,
    ) -> list[HostRiskBreakdown]:
        chains = attack_chains if attack_chains is not None else self.analyzer.analyze(alerts)
        baselines = baseline_records or []
        assets = asset_importance or {}

        alerts_by_host: dict[str, list[AlertRecord]] = {}
        for alert in alerts:
            if alert.src_ip:
                alerts_by_host.setdefault(alert.src_ip, []).append(alert)

        chains_by_host: dict[str, list[AttackChain]] = {}
        for chain in chains:
            chains_by_host.setdefault(chain.source_ip, []).append(chain)

        baselines_by_host = {record.src_ip: record for record in baselines if record.src_ip}
        baseline_activity = self._baseline_activity_scores(baselines)

        hosts = set(alerts_by_host) | set(chains_by_host) | set(baselines_by_host)
        results = [
            self._score_host(
                source_ip=host,
                alerts=alerts_by_host.get(host, []),
                chains=chains_by_host.get(host, []),
                baseline=baselines_by_host.get(host),
                baseline_activity_score=baseline_activity.get(host, 0),
                asset_score=self._asset_score(assets.get(host, 0)),
            )
            for host in hosts
        ]
        results.sort(key=lambda item: (item.score, item.severity_score, item.chain_score), reverse=True)
        return results[:limit] if limit is not None else results

    def _score_host(
        self,
        *,
        source_ip: str,
        alerts: list[AlertRecord],
        chains: list[AttackChain],
        baseline: BaselineRecord | None,
        baseline_activity_score: int,
        asset_score: int,
    ) -> HostRiskBreakdown:
        severity_score = self._severity_score(alerts)
        chain_score = max((chain.risk_score for chain in chains), default=0)
        baseline_score = max(baseline_activity_score, self._baseline_deviation_score(alerts))
        score = round(severity_score * 0.4 + chain_score * 0.3 + baseline_score * 0.2 + asset_score * 0.1)
        reasons = self._reasons(alerts, chains, baseline, asset_score)
        return HostRiskBreakdown(
            source_ip=source_ip,
            score=min(100, score),
            severity_score=severity_score,
            chain_score=chain_score,
            baseline_score=baseline_score,
            asset_score=asset_score,
            reasons=reasons,
        )

    def _severity_score(self, alerts: list[AlertRecord]) -> int:
        return min(100, sum(self.SEVERITY_POINTS.get(alert.severity.upper(), 0) for alert in alerts))

    def _baseline_deviation_score(self, alerts: list[AlertRecord]) -> int:
        deviation_alerts = [alert for alert in alerts if alert.rule_id in self.BASELINE_DEVIATION_RULES]
        if not deviation_alerts:
            return 0
        return min(100, 40 + len(deviation_alerts) * 20)

    def _baseline_activity_scores(self, records: list[BaselineRecord]) -> dict[str, int]:
        if not records:
            return {}

        max_packet_count = max((record.packet_count for record in records), default=0)
        max_connections = max((record.connection_count for record in records), default=0)
        max_destinations = max((record.unique_dst_ips for record in records), default=0)
        max_ports = max((record.unique_dst_ports for record in records), default=0)
        max_bytes = max((record.bytes_per_window for record in records), default=0)

        scores: dict[str, int] = {}
        for record in records:
            parts = [
                self._ratio_score(record.packet_count, max_packet_count),
                self._ratio_score(record.connection_count, max_connections),
                self._ratio_score(record.unique_dst_ips, max_destinations),
                self._ratio_score(record.unique_dst_ports, max_ports),
                self._ratio_score(record.bytes_per_window, max_bytes),
            ]
            scores[record.src_ip] = round(sum(parts) / len(parts))
        return scores

    def _ratio_score(self, value: int | float, maximum: int | float) -> int:
        if maximum <= 0:
            return 0
        return min(100, round(float(value) / float(maximum) * 100))

    def _asset_score(self, value: int) -> int:
        return min(100, max(0, int(value)))

    def _reasons(
        self,
        alerts: list[AlertRecord],
        chains: list[AttackChain],
        baseline: BaselineRecord | None,
        asset_score: int,
    ) -> list[str]:
        reasons: list[str] = []
        if alerts:
            counts: dict[str, int] = {}
            for alert in alerts:
                counts[alert.severity.upper()] = counts.get(alert.severity.upper(), 0) + 1
            ordered = [f"{severity}={counts[severity]}" for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if severity in counts]
            reasons.append("Alerts " + ", ".join(ordered))

        if chains:
            best_chain = max(chains, key=lambda chain: chain.risk_score)
            reasons.append(f"Chain {best_chain.summary}")

        if baseline:
            reasons.append(
                f"Baseline packets={baseline.packet_count}, destinations={baseline.unique_dst_ips}, bytes={baseline.bytes_per_window}"
            )

        if asset_score:
            reasons.append(f"Asset importance {asset_score}")

        return reasons or ["No notable risk signals"]
