from __future__ import annotations

from models import AlertRecord, HostConnectionSummary, HostSummary, HostTimelineEvent
from storage.analyst_repositories import AssetRepository, HostRepository
from storage.database import Database
from storage.repositories import AlertRepository


class HostProfileService:
    def __init__(self, database: Database) -> None:
        self.assets = AssetRepository(database)
        self.hosts = HostRepository(database)
        self.alerts = AlertRepository(database)

    def list_hosts(self, keyword: str = "", limit: int = 500) -> list[HostSummary]:
        packet_activity = self.hosts.packet_activity()
        alert_activity = self.hosts.alert_activity()
        assets = {asset.ip: asset for asset in self.assets.list_all()}
        asset_importance = {ip: asset.importance for ip, asset in assets.items()}

        host_ips = set(packet_activity) | set(alert_activity) | set(assets)
        lowered = keyword.strip().lower()
        summaries: list[HostSummary] = []
        for host_ip in host_ips:
            asset = assets.get(host_ip)
            if lowered and lowered not in " ".join(
                [host_ip, asset.display_name if asset else "", asset.role if asset else ""]
            ).lower():
                continue
            packet_data = packet_activity.get(host_ip, {})
            alert_data = alert_activity.get(host_ip, {})
            simple_risk = min(100, int(alert_data.get("critical_count", 0)) * 20 + int(alert_data.get("alert_count", 0)) * 2 + asset_importance.get(host_ip, 0) // 10)
            summaries.append(
                HostSummary(
                    ip=host_ip,
                    display_name=asset.display_name if asset else "",
                    role=asset.role if asset else "Other",
                    importance=asset.importance if asset else 0,
                    risk_score=simple_risk,
                    packet_count=int(packet_data.get("packet_count", 0)),
                    alert_count=int(alert_data.get("alert_count", 0)),
                    critical_count=int(alert_data.get("critical_count", 0)),
                    incoming_packets=int(packet_data.get("incoming_packets", 0)),
                    outgoing_packets=int(packet_data.get("outgoing_packets", 0)),
                    last_seen=max(str(packet_data.get("last_seen", "")), str(alert_data.get("last_seen", ""))),
                    risk_reasons=[],
                )
            )
        summaries.sort(key=lambda item: (item.risk_score, item.alert_count, item.packet_count), reverse=True)
        return summaries[:limit]

    def get_host(self, host_ip: str) -> HostSummary | None:
        return next((host for host in self.list_hosts(limit=10_000) if host.ip == host_ip), None)

    def connections(self, host_ip: str) -> list[HostConnectionSummary]:
        return self.hosts.connections(host_ip)

    def alerts_for_host(self, host_ip: str, limit: int = 1_000) -> list[AlertRecord]:
        return self.alerts.list_for_host(host_ip, limit=limit)

    def timeline(self, host_ip: str) -> list[HostTimelineEvent]:
        return self.hosts.timeline(host_ip)

    def protocol_distribution(self, host_ip: str) -> dict[str, int]:
        return self.hosts.protocol_distribution(host_ip)

    def port_distribution(self, host_ip: str) -> list[tuple[int, int]]:
        return self.hosts.port_distribution(host_ip)

