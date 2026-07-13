from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from uuid import uuid4

from app.constants import DEFAULT_DATABASE_PATH
from detection.analysis.alert_trend import AlertTrendAnalyzer
from detection.analysis.host_profile import HostProfileService
from endpoint_security import EndpointPostureService, FileIntegrityService, ProcessInventoryService
from modern_ui.capture_session import CaptureSessionService, default_capture_options, parse_capture_options
from modern_ui.llm_guidance import LlmGuidanceError, LlmGuidanceService
from modern_ui.pcap_import import PcapImportService
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository


class LocalApiServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], database: Database) -> None:
        super().__init__(address, LocalApiHandler)
        self.capture_service = CaptureSessionService(database)
        self.database = database
        self.alerts = AlertRepository(database)
        self.packets = PacketRepository(database)
        self.host_profiles = HostProfileService(database)
        self.alert_trends = AlertTrendAnalyzer()
        self.pcap_import = PcapImportService(database)
        self.posture_service = EndpointPostureService()
        self.process_inventory = ProcessInventoryService()
        self.file_integrity = FileIntegrityService(database.path.parent / "endpoint_security")
        self.llm_guidance = LlmGuidanceService()

    def server_close(self) -> None:
        self.capture_service.shutdown()
        self.pcap_import.shutdown()
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
                self._send_json({"ok": True, "service": "Lightweight IDS local API"})
            elif parsed.path == "/api/capture/interfaces":
                self._send_json({"interfaces": self.server.capture_service.list_interfaces()})
            elif parsed.path == "/api/capture/status":
                self._send_json(self.server.capture_service.status())
            elif parsed.path == "/api/pcap/status":
                self._send_json(self.server.pcap_import.status())
            elif parsed.path == "/api/dashboard":
                self._send_json(self._dashboard_payload())
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
            elif parsed.path == "/api/llm/defense-guidance":
                self._send_json(self.server.llm_guidance.generate(payload))
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


def _positive_int(value: str, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _path_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("paths must be an array of strings")
    return value


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
