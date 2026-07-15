from __future__ import annotations

import argparse
import ipaddress
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from uuid import uuid4

from app.constants import DEFAULT_DATABASE_PATH
from detection.analysis.alert_trend import AlertTrendAnalyzer
from detection.analysis.host_profile import HostProfileService
from endpoint_security import EndpointPostureService, FileIntegrityService, ProcessInventoryService, ResourceThreatMonitorService, RuntimeHealthService
from modern_ui.capture_session import CaptureSessionService, default_capture_options, parse_capture_options
from modern_ui.llm_guidance import LlmGuidanceError, LlmGuidanceService
from modern_ui.pcap_import import PcapImportService
from modern_ui.secret_store import WindowsDpapiSecretStore
from modern_ui.security_event_monitor import SecurityEventMonitorService
from models import RuleRecord
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository, RuleRepository, SecurityEventRepository, SettingsRepository


LOCAL_API_VERSION = 5
LOCAL_API_CAPABILITIES = [
    "capture-v1",
    "endpoint-security-v1",
    "system-health-v1",
    "topology-v1",
    "llm-guidance-v1",
    "timeline-v1",
    "resource-monitor-v1",
]


class LocalApiServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], database: Database) -> None:
        super().__init__(address, LocalApiHandler)
        self.capture_service = CaptureSessionService(database)
        self.database = database
        self.started_at = monotonic()
        self.alerts = AlertRepository(database)
        self.packets = PacketRepository(database)
        self.rules = RuleRepository(database)
        self.settings = SettingsRepository(database)
        self.host_profiles = HostProfileService(database)
        self.alert_trends = AlertTrendAnalyzer()
        self.pcap_import = PcapImportService(database)
        self.posture_service = EndpointPostureService()
        self.process_inventory = ProcessInventoryService()
        self.file_integrity = FileIntegrityService(database.path.parent / "endpoint_security")
        self.runtime_health = RuntimeHealthService(database.path.parent)
        self.resource_monitor = ResourceThreatMonitorService(database, self.runtime_health.collect)
        self.security_events = SecurityEventRepository(database)
        self.security_event_monitor = SecurityEventMonitorService(
            database,
            poll_seconds=self.settings.get_int("security_event_poll_seconds", 5),
        )
        self.llm_guidance = LlmGuidanceService()
        self.secret_store = WindowsDpapiSecretStore()
        if self.settings.get_bool("security_event_monitor_enabled", False):
            try:
                self.security_event_monitor.start()
            except RuntimeError:
                pass
        self.resource_monitor.start()

    def server_close(self) -> None:
        self.capture_service.shutdown()
        self.pcap_import.shutdown()
        self.security_event_monitor.shutdown()
        self.resource_monitor.shutdown()
        super().server_close()


class LocalApiHandler(BaseHTTPRequestHandler):
    server: LocalApiServer
    protocol_version = "HTTP/1.1"

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/health":
                self._send_json(
                    {
                        "ok": True,
                        "service": "Lightweight IDS local API",
                        "apiVersion": LOCAL_API_VERSION,
                        "capabilities": LOCAL_API_CAPABILITIES,
                        "database": str(self.server.database.path.resolve()),
                        "pid": os.getpid(),
                    }
                )
            elif parsed.path == "/api/settings":
                self._send_json(_settings_payload(self.server.settings))
            elif parsed.path == "/api/rules":
                self._send_json({"records": [_rule_payload(record) for record in self.server.rules.list_all()]})
            elif parsed.path == "/api/capture/interfaces":
                self._send_json({"interfaces": self.server.capture_service.list_interfaces()})
            elif parsed.path == "/api/capture/status":
                self._send_json(self.server.capture_service.status())
            elif parsed.path == "/api/pcap/status":
                self._send_json(self.server.pcap_import.status())
            elif parsed.path == "/api/dashboard":
                self._send_json(self._dashboard_payload())
            elif parsed.path == "/api/timeline":
                query = parse_qs(parsed.query)
                self._send_json(self._event_timeline_payload(min(_positive_int(query.get("limit", ["500"])[0], 500), 2_000)))
            elif parsed.path == "/api/topology":
                self._send_json(self._topology_payload())
            elif parsed.path == "/api/packets":
                query = parse_qs(parsed.query)
                self._send_json(
                    self.server.capture_service.packets_since(
                        _positive_int(query.get("after", ["0"])[0], 0),
                        _positive_int(query.get("limit", ["250"])[0], 250),
                    )
                )
            elif parsed.path == "/api/capture/alerts":
                query = parse_qs(parsed.query)
                self._send_json(
                    self.server.capture_service.alerts_since(
                        _positive_int(query.get("after", ["0"])[0], 0),
                        _positive_int(query.get("limit", ["100"])[0], 100),
                    )
                )
            elif parsed.path == "/api/alerts":
                query = parse_qs(parsed.query)
                self._send_json(
                    {
                        "records": [
                            _alert_payload(alert)
                            for alert in self.server.alerts.list_all(
                                severity=query.get("severity", [""])[0] or None,
                                keyword=query.get("query", [""])[0] or None,
                                limit=min(_positive_int(query.get("limit", ["500"])[0], 500), 2_000),
                            )
                        ]
                    }
                )
            elif parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/packets"):
                alert_id = _route_id(parsed.path, "/api/alerts/", "/packets")
                alert = self.server.alerts.get(alert_id)
                if alert is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "Alert not found.")
                    return
                self._send_json(
                    {
                        "records": [
                            _packet_payload(packet)
                            for packet in self.server.packets.list_related_to_alert(
                                alert,
                                limit=min(_positive_int(parse_qs(parsed.query).get("limit", ["500"])[0], 500), 1_000),
                            )
                        ]
                    }
                )
            elif parsed.path == "/api/hosts":
                query = parse_qs(parsed.query)
                self._send_json(
                    {
                        "records": [
                            _host_payload(host)
                            for host in self.server.host_profiles.list_hosts(
                                keyword=query.get("query", [""])[0],
                                limit=min(_positive_int(query.get("limit", ["500"])[0], 500), 2_000),
                            )
                        ]
                    }
                )
            elif parsed.path.startswith("/api/hosts/"):
                try:
                    self._send_json(self._host_payload(unquote(parsed.path.removeprefix("/api/hosts/"))))
                except LookupError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
            elif parsed.path == "/api/security/posture":
                self._send_json({"checks": self.server.posture_service.collect()})
            elif parsed.path == "/api/security/processes":
                query = parse_qs(parsed.query)
                self._send_json({"processes": self.server.process_inventory.list_processes(_positive_int(query.get("limit", ["200"])[0], 200))})
            elif parsed.path == "/api/security/integrity/status":
                self._send_json(self.server.file_integrity.status())
            elif parsed.path == "/api/system/health":
                self._send_json(self._system_health_payload())
            elif parsed.path == "/api/security/events/status":
                self._send_json(self.server.security_event_monitor.status())
            elif parsed.path == "/api/security/events":
                query = parse_qs(parsed.query)
                event_id_text = query.get("eventId", [""])[0].strip()
                event_id = int(event_id_text) if event_id_text.isdigit() else None
                events = self.server.security_events.list_all(
                    keyword=query.get("query", [""])[0] or None,
                    severity=query.get("severity", [""])[0] or None,
                    channel=query.get("channel", [""])[0] or None,
                    event_id=event_id,
                    limit=min(_positive_int(query.get("limit", ["500"])[0], 500), 2_000),
                )
                self._send_json(
                    {
                        "records": [_security_event_payload(event) for event in events],
                        "total": len(events),
                        "status": self.server.security_event_monitor.status(),
                    }
                )
            elif parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/security-event"):
                alert_id = _route_id(parsed.path, "/api/alerts/", "/security-event")
                event = self.server.security_events.get_for_alert(alert_id)
                self._send_json({"record": None if event is None else _security_event_payload(event)})
            else:
                self._send_error(HTTPStatus.NOT_FOUND, "Endpoint not found.")
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/pcap/import":
                self._send_json(self._receive_pcap_upload(), HTTPStatus.ACCEPTED)
                return
            payload = self._read_json()
            if parsed.path == "/api/capture/start":
                options = parse_capture_options(payload, default_capture_options(self.server.database))
                self._send_json(self.server.capture_service.start(options), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/settings":
                self._update_settings(payload)
                self._send_json(_settings_payload(self.server.settings))
            elif parsed.path.startswith("/api/rules/"):
                rule_id = unquote(parsed.path.removeprefix("/api/rules/"))
                self._send_json({"record": self._update_rule(rule_id, payload)})
            elif parsed.path == "/api/statistics/reset":
                self._reset_statistics()
                self._send_json({"reset": True, "dashboard": self._dashboard_payload()})
            elif parsed.path == "/api/capture/pause":
                self._send_json(self.server.capture_service.pause())
            elif parsed.path == "/api/capture/resume":
                self._send_json(self.server.capture_service.resume())
            elif parsed.path == "/api/capture/stop":
                self._send_json(self.server.capture_service.stop())
            elif parsed.path == "/api/capture/validate-filter":
                expression = payload.get("filterExpression", "")
                if not isinstance(expression, str):
                    raise ValueError("filterExpression must be a string")
                self._send_json(self.server.capture_service.validate_filter(expression))
            elif parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/status"):
                alert = self.server.alerts.get(_route_id(parsed.path, "/api/alerts/", "/status"))
                if alert is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "Alert not found.")
                    return
                status = payload.get("status")
                if status not in {"unconfirmed", "confirmed", "ignored"}:
                    raise ValueError("status must be unconfirmed, confirmed, or ignored")
                self.server.alerts.update_status(int(alert.id or 0), status)
                refreshed = self.server.alerts.get(int(alert.id or 0))
                self._send_json({"record": _alert_payload(refreshed or alert)})
            elif parsed.path == "/api/security/integrity/baseline":
                self._send_json(self.server.file_integrity.create_baseline(_path_list(payload.get("paths"))))
            elif parsed.path == "/api/security/integrity/scan":
                self._send_json(self.server.file_integrity.scan())
            elif parsed.path == "/api/security/events/start":
                status = self.server.security_event_monitor.start()
                self.server.settings.set("security_event_monitor_enabled", "true")
                self._send_json(status)
            elif parsed.path == "/api/security/events/stop":
                self.server.settings.set("security_event_monitor_enabled", "false")
                self._send_json(self.server.security_event_monitor.stop())
            elif parsed.path == "/api/security/events/refresh":
                self._send_json(self.server.security_event_monitor.refresh_once())
            elif parsed.path == "/api/llm/defense-guidance":
                alert = payload.get("alert")
                if not isinstance(alert, dict):
                    raise LlmGuidanceError("alert must be a JSON object")
                language = payload.get("language", "en")
                if language not in {"en", "zh"}:
                    raise LlmGuidanceError("language must be en or zh")
                protected_key = self.server.settings.get("llm_api_key_protected")
                if not protected_key:
                    raise LlmGuidanceError("Save an API key in Settings before requesting guidance.")
                self._send_json(
                    self.server.llm_guidance.generate(
                        {
                            "settings": {
                                "baseUrl": self.server.settings.get("llm_base_url", "https://api.openai.com/v1"),
                                "apiKey": self.server.secret_store.unprotect(protected_key),
                                "model": self.server.settings.get("llm_model", "gpt-4.1-mini"),
                            },
                            "alert": alert,
                            "language": language,
                        }
                    )
                )
            else:
                self._send_error(HTTPStatus.NOT_FOUND, "Endpoint not found.")
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
        except RuntimeError as exc:
            self._send_error(HTTPStatus.CONFLICT, str(exc))
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _update_settings(self, payload: dict[str, Any]) -> None:
        values: dict[str, str] = {}
        if "autoSavePackets" in payload:
            values["auto_save_packets"] = _bool_setting(payload, "autoSavePackets")
        if "realtimeDetection" in payload:
            values["enable_realtime_detection"] = _bool_setting(payload, "realtimeDetection")
        if "alertCooldownSeconds" in payload:
            values["alert_cooldown_seconds"] = str(max(0, min(3_600, _setting_integer(payload, "alertCooldownSeconds"))))
        if "minimumAlertSeverity" in payload:
            severity = str(payload["minimumAlertSeverity"]).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("minimumAlertSeverity must be LOW, MEDIUM, HIGH, or CRITICAL")
            values["minimum_alert_severity"] = severity
        if "securityEventPollSeconds" in payload:
            seconds = max(2, min(300, _setting_integer(payload, "securityEventPollSeconds")))
            values["security_event_poll_seconds"] = str(seconds)
            self.server.security_event_monitor.set_poll_seconds(seconds)
        if "securityEventMonitorEnabled" in payload:
            enabled = payload["securityEventMonitorEnabled"]
            if not isinstance(enabled, bool):
                raise ValueError("securityEventMonitorEnabled must be a boolean")
            if enabled:
                self.server.security_event_monitor.start()
            else:
                self.server.security_event_monitor.stop()
            values["security_event_monitor_enabled"] = "true" if enabled else "false"
        if "llmBaseUrl" in payload:
            base_url = _setting_text(payload, "llmBaseUrl", 1_000).rstrip("/")
            parsed_url = urlparse(base_url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                raise ValueError("llmBaseUrl must be a valid http or https URL")
            values["llm_base_url"] = base_url
        if "llmModel" in payload:
            values["llm_model"] = _setting_text(payload, "llmModel", 200)
        if "llmApiKey" in payload and payload.get("clearLlmApiKey") is True:
            raise ValueError("llmApiKey and clearLlmApiKey cannot be used together")
        if "llmApiKey" in payload:
            api_key = _setting_text(payload, "llmApiKey", 1_000)
            values["llm_api_key_protected"] = self.server.secret_store.protect(api_key)
        if "clearLlmApiKey" in payload:
            clear_key = payload["clearLlmApiKey"]
            if not isinstance(clear_key, bool):
                raise ValueError("clearLlmApiKey must be a boolean")
            if clear_key:
                values["llm_api_key_protected"] = ""
        self.server.settings.set_many(values)

    def _update_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        current = next((record for record in self.server.rules.list_all() if record.id == rule_id), None)
        if current is None:
            raise ValueError("Rule not found.")
        threshold = max(1, _optional_int(payload, "threshold", current.threshold))
        if rule_id in {"SUSTAINED_CPU_LOAD", "SUSTAINED_GPU_LOAD"}:
            threshold = min(100, threshold)
        updated = RuleRecord(
            id=current.id,
            name=current.name,
            category=current.category,
            severity=current.severity,
            enabled=_optional_bool(payload, "enabled", current.enabled),
            threshold=threshold,
            time_window=max(0, _optional_int(payload, "timeWindow", current.time_window)),
            description=current.description,
        )
        self.server.rules.update_rule(updated)
        return _rule_payload(updated)

    def _reset_statistics(self) -> None:
        if self.server.capture_service.status().get("state") != "stopped":
            raise RuntimeError("Stop live capture before resetting statistics.")
        if self.server.pcap_import.status().get("state") == "importing":
            raise RuntimeError("Wait for the PCAP import to finish before resetting statistics.")
        security_monitor_running = self.server.security_event_monitor.status().get("state") == "running"
        self.server.resource_monitor.stop()
        if security_monitor_running:
            self.server.security_event_monitor.stop()
        with self.server.database.connect() as connection:
            connection.execute("DELETE FROM alerts")
            connection.execute("DELETE FROM packets")
            connection.execute("DELETE FROM baselines")
            connection.execute("DELETE FROM security_events")
            connection.execute(
                "DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'packets', 'baselines', 'security_events')"
            )
        self.server.capture_service.reset_statistics()
        self.server.pcap_import.reset_statistics()
        self.server.security_event_monitor.reset_statistics()
        self.server.resource_monitor.reset_statistics()
        self.server.resource_monitor.start()
        if security_monitor_running:
            self.server.security_event_monitor.start()

    def _dashboard_payload(self) -> dict[str, Any]:
        recent_alerts = self.server.alerts.list_all(limit=500)
        hosts = self.server.host_profiles.list_hosts(limit=500)
        alert_counts = dict(self.server.alerts.count_by_time_bucket(bucket="hour", limit=12))
        packet_counts = dict(self.server.packets.count_by_time_bucket(bucket="hour", limit=12))
        severity_counts = self.server.alerts.count_by_severity()
        status_counts = self.server.alerts.count_by_status()
        buckets = sorted(set(alert_counts) | set(packet_counts))[-12:]
        trend = [
            {
                "time": _bucket_label(bucket),
                "bucket": bucket,
                "alerts": alert_counts.get(bucket, 0),
                "packets": packet_counts.get(bucket, 0),
                "spike": point.is_spike,
            }
            for bucket, point in zip(
                buckets,
                self.server.alert_trends.analyze([(bucket, alert_counts.get(bucket, 0)) for bucket in buckets]),
                strict=True,
            )
        ]
        open_alerts = status_counts.get("unconfirmed", 0)
        high_priority = severity_counts.get("HIGH", 0) + severity_counts.get("CRITICAL", 0)
        high_risk = [host for host in hosts if host.risk_score >= 70]
        return {
            "capture": self.server.capture_service.status(),
            "statistics": {
                "packetTotal": self.server.packets.count(),
                "alertTotal": self.server.alerts.count(),
                "openAlerts": open_alerts,
                "highPriorityAlerts": high_priority,
                "highRiskHosts": len(high_risk),
                "lastHourPackets": packet_counts.get(buckets[-1], 0) if buckets else 0,
            },
            "trend": trend,
            "severityDistribution": [
                {"name": severity.title(), "value": count, "color": _severity_color(severity)}
                for severity, count in severity_counts.items()
            ],
            "highRiskHosts": [_host_payload(host) for host in hosts[:4]],
            "recentAlerts": [_alert_payload(alert) for alert in recent_alerts[:4]],
        }

    def _event_timeline_payload(self, limit: int) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        for alert in self.server.alerts.list_all(limit=limit):
            records.append(
                {
                    "id": f"alert-{alert.id}",
                    "timestamp": alert.timestamp,
                    "kind": "alert",
                    "severity": alert.severity,
                    "headline": alert.rule_name,
                    "detail": alert.description,
                    "source": _endpoint(alert.src_ip, alert.src_port),
                    "destination": _endpoint(alert.dst_ip, alert.dst_port) if alert.dst_ip else "",
                }
            )
        for packet in self.server.packets.list_recent(limit=limit):
            records.append(
                {
                    "id": f"packet-{packet.id}",
                    "timestamp": packet.timestamp,
                    "kind": "packet",
                    "headline": f"{packet.protocol} {packet.raw_summary}".strip()[:240],
                    "detail": f"{_endpoint(packet.src_ip, packet.src_port)} -> {_endpoint(packet.dst_ip, packet.dst_port)} - {packet.length} bytes",
                    "source": _endpoint(packet.src_ip, packet.src_port),
                    "destination": _endpoint(packet.dst_ip, packet.dst_port),
                }
            )
        for event in self.server.security_events.list_all(limit=limit):
            records.append(
                {
                    "id": f"system-{event.id}",
                    "timestamp": event.timestamp,
                    "kind": "system",
                    "severity": event.severity,
                    "headline": event.summary or f"Windows event {event.event_id}",
                    "detail": f"{event.channel} - {event.provider}".strip(" -"),
                    "source": event.computer or event.user or "local host",
                    "destination": "",
                }
            )
        records.sort(key=lambda record: str(record["timestamp"]), reverse=True)
        return {"records": records[:limit]}

    def _topology_payload(self) -> dict[str, Any]:
        connections = self.server.packets.topology_connections(limit=250)
        if not self.server.capture_service.status().get("savePackets", True):
            connections = _merge_topology_connections(
                connections,
                self.server.capture_service.topology_connections(),
                limit=250,
            )
        host_by_ip = {host.ip: host for host in self.server.host_profiles.list_hosts(limit=1_000)}
        observed_ips = {
            str(connection[key])
            for connection in connections
            for key in ("source", "target")
        }
        packet_activity: dict[str, int] = {ip: 0 for ip in observed_ips}
        last_seen: dict[str, str] = {ip: "" for ip in observed_ips}
        for connection in connections:
            for key in ("source", "target"):
                ip = str(connection[key])
                packet_activity[ip] += int(connection["packets"])
                last_seen[ip] = max(last_seen[ip], str(connection["last_seen"]))
        nodes = []
        for ip in sorted(observed_ips):
            host = host_by_ip.get(ip)
            role = str(host.role or "Other") if host else "Other"
            nodes.append(
                {
                    "id": ip,
                    "label": str(host.display_name or ip) if host else ip,
                    "ip": ip,
                    "kind": _topology_kind(ip, role),
                    "role": role,
                    "risk": int(host.risk_score or 0) if host else 0,
                    "importance": int(host.importance or 0) if host else 0,
                    "packets": packet_activity[ip],
                    "alerts": int(host.alert_count or 0) if host else 0,
                    "lastSeen": max(str(host.last_seen or "") if host else "", last_seen[ip]),
                }
            )
        return {
            "nodes": nodes,
            "edges": [
                {
                    "source": connection["source"],
                    "target": connection["target"],
                    "protocol": connection["protocol"],
                    "packets": connection["packets"],
                    "bytes": connection["bytes"],
                    "lastSeen": connection["last_seen"],
                }
                for connection in connections
            ],
        }

    def _system_health_payload(self) -> dict[str, Any]:
        rules = self.server.rules.list_all()
        feedback = self.server.alerts.rule_feedback()
        capture = self.server.capture_service.status()
        try:
            database_bytes = self.server.database.path.stat().st_size
        except OSError:
            database_bytes = 0
        return {
            "system": self.server.runtime_health.collect(),
            "resourceMonitor": self.server.resource_monitor.status(),
            "engine": {
                "apiVersion": LOCAL_API_VERSION,
                "uptimeSeconds": max(0, int(monotonic() - self.server.started_at)),
                "databaseBytes": database_bytes,
                "rulesLoaded": len(rules),
                "activeRules": sum(1 for rule in rules if rule.enabled),
                "packetsStored": self.server.packets.count(),
                "alertsStored": self.server.alerts.count(),
                "captureState": capture["state"],
                "captureInterface": capture["interface"],
                "packetsPerSecond": capture["packetsPerSecond"],
                "sessionPackets": capture["packetTotal"],
                "sessionAlerts": capture["alertTotal"],
            },
            "detectors": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "enabled": rule.enabled,
                    "severity": rule.severity,
                    "hits": int(feedback.get(rule.id, {}).get("total", 0)),
                }
                for rule in rules
            ],
        }

    def _host_payload(self, host_ip: str) -> dict[str, Any]:
        host = self.server.host_profiles.get_host(host_ip)
        if host is None:
            raise LookupError("Host not found.")
        return {
            "host": _host_payload(host),
            "protocols": [
                {"name": protocol, "value": count}
                for protocol, count in self.server.host_profiles.protocol_distribution(host_ip).items()
            ],
            "ports": [
                {"port": port, "count": count}
                for port, count in self.server.host_profiles.port_distribution(host_ip)
            ],
            "connections": [
                {
                    "peer": item.peer_ip,
                    "direction": item.direction,
                    "protocol": item.protocol,
                    "port": item.port,
                    "packets": item.packet_count,
                    "lastSeen": item.last_seen,
                }
                for item in self.server.host_profiles.connections(host_ip)
            ],
            "alerts": [_alert_payload(alert) for alert in self.server.host_profiles.alerts_for_host(host_ip, limit=100)],
            "timeline": [
                {
                    "timestamp": item.timestamp,
                    "type": item.event_type,
                    "direction": item.direction,
                    "peer": item.peer_ip,
                    "summary": item.summary,
                    "severity": item.severity,
                }
                for item in self.server.host_profiles.timeline(host_ip)[:100]
            ],
        }

    def _read_json(self) -> dict[str, Any]:
        content_length = _positive_int(self.headers.get("Content-Length", "0"), 0)
        if content_length == 0:
            return {}
        payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _receive_pcap_upload(self) -> dict[str, Any]:
        content_length = _positive_int(self.headers.get("Content-Length", "0"), 0)
        maximum_bytes = 512 * 1024 * 1024
        if not content_length:
            raise ValueError("Choose a non-empty PCAP file to import.")
        if content_length > maximum_bytes:
            raise ValueError("The PCAP file exceeds the 512 MB local import limit.")

        original_name = Path(unquote(self.headers.get("X-Filename", "capture.pcap"))).name
        suffix = Path(original_name).suffix.lower()
        if suffix not in PcapImportService.ALLOWED_EXTENSIONS:
            raise ValueError("Only .pcap, .pcapng, and .cap files can be imported.")

        upload_dir = self.server.database.path.parent / "modern_ui_uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        upload_path = upload_dir / f"{uuid4().hex}{suffix}"
        try:
            remaining = content_length
            with upload_path.open("wb") as stream:
                while remaining:
                    chunk = self.rfile.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise ValueError("The PCAP upload ended before all bytes were received.")
                    stream.write(chunk)
                    remaining -= len(chunk)
            return self.server.pcap_import.start(upload_path, filename=original_name, remove_after=True)
        except Exception:
            upload_path.unlink(missing_ok=True)
            raise

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message}, status)

    def _send_cors_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in {"http://127.0.0.1:4173", "http://localhost:4173"}:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")


def _route_id(path: str, prefix: str, suffix: str) -> int:
    value = path.removeprefix(prefix).removesuffix(suffix)
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError("A numeric record ID is required.") from exc


def _endpoint(ip: str | None, port: int | None) -> str:
    value = ip or "Unknown"
    return f"{value}:{port}" if port is not None else value


def _alert_payload(alert: Any) -> dict[str, Any]:
    return {
        "id": int(alert.id or 0),
        "timestamp": alert.timestamp,
        "severity": str(alert.severity or "INFO").upper(),
        "ruleId": alert.rule_id,
        "ruleName": alert.rule_name,
        "source": _endpoint(alert.src_ip, alert.src_port),
        "destination": _endpoint(alert.dst_ip, alert.dst_port),
        "protocol": alert.protocol or "UNKNOWN",
        "description": alert.description,
        "evidence": alert.evidence,
        "status": alert.status or "unconfirmed",
    }


def _packet_payload(packet: Any) -> dict[str, Any]:
    return {
        "id": int(packet.id or 0),
        "timestamp": packet.timestamp,
        "source": _endpoint(packet.src_ip, packet.src_port),
        "destination": _endpoint(packet.dst_ip, packet.dst_port),
        "protocol": packet.protocol or "UNKNOWN",
        "length": int(packet.length or 0),
        "flags": packet.tcp_flags or "",
        "summary": packet.raw_summary,
        "details": {
            "sourceIp": packet.src_ip,
            "destinationIp": packet.dst_ip,
            "sourcePort": packet.src_port,
            "destinationPort": packet.dst_port,
            "dnsQuery": packet.dns_query,
            "httpMethod": packet.http_method,
            "httpHost": packet.http_host,
            "httpPath": packet.http_path,
        },
    }


def _host_payload(host: Any) -> dict[str, Any]:
    display_name = host.display_name or host.ip
    return {
        "ip": host.ip,
        "name": display_name,
        "role": host.role or "Other",
        "risk": int(host.risk_score or 0),
        "importance": int(host.importance or 0),
        "packets": int(host.packet_count or 0),
        "alerts": int(host.alert_count or 0),
        "incomingPackets": int(host.incoming_packets or 0),
        "outgoingPackets": int(host.outgoing_packets or 0),
        "lastSeen": host.last_seen,
        "riskReasons": list(host.risk_reasons),
    }


def _bucket_label(bucket: str) -> str:
    return bucket[-5:] if len(bucket) >= 5 and ":" in bucket else bucket


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#b42318",
        "HIGH": "#e5484d",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#2f8f66",
    }.get(severity.upper(), "#7a8996")


def _topology_kind(ip: str, role: str) -> str:
    normalized_role = role.strip().lower()
    if normalized_role == "gateway":
        return "gateway"
    if normalized_role in {"server", "database", "domain controller"}:
        return "server"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "external"
    if not (address.is_private or address.is_loopback or address.is_link_local):
        return "external"
    return "workstation"


def _merge_topology_connections(
    persisted: list[dict[str, object]],
    live: list[dict[str, object]],
    *,
    limit: int,
) -> list[dict[str, object]]:
    merged: dict[tuple[str, str, str], dict[str, object]] = {}
    for connection in [*persisted, *live]:
        key = (str(connection["source"]), str(connection["target"]), str(connection["protocol"]))
        item = merged.setdefault(
            key,
            {"source": key[0], "target": key[1], "protocol": key[2], "packets": 0, "bytes": 0, "last_seen": ""},
        )
        item["packets"] = int(item["packets"]) + int(connection["packets"])
        item["bytes"] = int(item["bytes"]) + int(connection["bytes"])
        item["last_seen"] = max(str(item["last_seen"]), str(connection["last_seen"]))
    return sorted(merged.values(), key=lambda item: (int(item["packets"]), str(item["last_seen"])), reverse=True)[:limit]


def _positive_int(value: str, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _path_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("paths must be an array of strings")
    return value


def _settings_payload(settings: SettingsRepository) -> dict[str, Any]:
    return {
        "autoSavePackets": settings.get_bool("auto_save_packets", True),
        "realtimeDetection": settings.get_bool("enable_realtime_detection", True),
        "alertCooldownSeconds": settings.get_int("alert_cooldown_seconds", 10),
        "minimumAlertSeverity": settings.get("minimum_alert_severity", "LOW").upper(),
        "securityEventMonitorEnabled": settings.get_bool("security_event_monitor_enabled", False),
        "securityEventPollSeconds": settings.get_int("security_event_poll_seconds", 5),
        "llmBaseUrl": settings.get("llm_base_url", "https://api.openai.com/v1"),
        "llmModel": settings.get("llm_model", "gpt-4.1-mini"),
        "llmApiKeyConfigured": bool(settings.get("llm_api_key_protected")),
    }


def _security_event_payload(event: Any) -> dict[str, Any]:
    return {
        "id": int(event.id or 0),
        "timestamp": event.timestamp,
        "channel": event.channel,
        "eventId": int(event.event_id or 0),
        "recordId": int(event.record_id or 0),
        "provider": event.provider,
        "computer": event.computer,
        "level": event.level,
        "user": event.user,
        "sourceIp": event.source_ip,
        "logonType": event.logon_type,
        "processName": event.process_name,
        "commandLine": event.command_line,
        "summary": event.summary,
        "details": dict(event.details),
        "severity": str(event.severity or "INFO").upper(),
        "alertId": event.alert_id,
    }


def _rule_payload(rule: RuleRecord) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "threshold": rule.threshold,
        "timeWindow": rule.time_window,
        "description": rule.description,
    }


def _optional_int(payload: dict[str, Any], key: str, default: int) -> int:
    if key not in payload:
        return default
    try:
        return int(payload[key])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc


def _optional_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _setting_integer(payload: dict[str, Any], key: str) -> int:
    try:
        return int(payload[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc


def _setting_text(payload: dict[str, Any], key: str, maximum: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} is required")
    if len(value) > maximum:
        raise ValueError(f"{key} is too long")
    return value.strip()


def _bool_setting(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return "true" if value else "false"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Lightweight IDS local API for the React prototype.")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE_PATH)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("The local API only supports loopback hosts.")

    database = Database(args.database)
    database.initialize()
    server = LocalApiServer((args.host, args.port), database)
    print(f"Lightweight IDS local API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
