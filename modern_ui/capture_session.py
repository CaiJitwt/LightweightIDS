from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from threading import Event, RLock, Thread
from time import monotonic
from typing import Any

from capture.interface_manager import InterfaceManager
from capture.live_capture import LiveCapture
from capture.packet_filter import PacketFilter, PacketFilterError
from detection.engine import DetectionEngine
from models import AlertRecord, PacketRecord
from parser.packet_parser import PacketParser
from storage.analyst_repositories import AssetRepository
from storage.blocklist_repository import BlocklistEntryRepository
from storage.database import Database
from storage.repositories import (
    CustomRuleRepository,
    RuleRepository,
    SettingsRepository,
    TrafficRepository,
)


@dataclass(frozen=True)
class CaptureStartOptions:
    interface: str | None = None
    filter_expression: str = ""
    save_packets: bool = True
    detection_enabled: bool = True
    alert_cooldown_seconds: int = 10


class CaptureSessionService:
    """One capture owner shared by local UI clients.

    The service deliberately keeps capture and detection in Python. Browser clients
    can poll its bounded event buffers without becoming part of the packet path.
    """

    def __init__(self, database: Database, max_event_records: int = 2_000) -> None:
        self.database = database
        self.interface_manager = InterfaceManager()
        self.max_event_records = max_event_records
        self._lock = RLock()
        self._stop_event = Event()
        self._paused_event = Event()
        self._thread: Thread | None = None
        self._capture: LiveCapture | None = None
        self._state = "stopped"
        self._error = ""
        self._started_at: float | None = None
        self._options = CaptureStartOptions()
        self._packet_total = 0
        self._alert_total = 0
        self._skipped_total = 0
        self._saved_packet_total = 0
        self._saved_alert_total = 0
        self._sequence = 0
        self._recent_packets: deque[dict[str, Any]] = deque(maxlen=max_event_records)
        self._recent_alerts: deque[dict[str, Any]] = deque(maxlen=max_event_records)

    def list_interfaces(self) -> list[str]:
        return self.interface_manager.list_interfaces()

    def validate_filter(self, expression: str) -> dict[str, str]:
        compiled = PacketFilter.compile(expression)
        return {"expression": compiled.expression, "bpf": compiled.capture_filter}

    def start(self, options: CaptureStartOptions) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("A live capture session is already running.")

            compiled = PacketFilter.compile(options.filter_expression)
            self._options = CaptureStartOptions(
                interface=options.interface or None,
                filter_expression=compiled.expression,
                save_packets=options.save_packets,
                detection_enabled=options.detection_enabled,
                alert_cooldown_seconds=max(0, options.alert_cooldown_seconds),
            )
            self._stop_event.clear()
            self._paused_event.clear()
            self._state = "running"
            self._error = ""
            self._started_at = monotonic()
            self._packet_total = 0
            self._alert_total = 0
            self._skipped_total = 0
            self._saved_packet_total = 0
            self._saved_alert_total = 0
            self._recent_packets.clear()
            self._recent_alerts.clear()
            self._thread = Thread(target=self._run, name="modern-ids-capture", daemon=True)
            self._thread.start()
        return self.status()

    def pause(self) -> dict[str, Any]:
        with self._lock:
            if self._state != "running":
                raise RuntimeError("Capture is not running.")
            self._paused_event.set()
            self._state = "paused"
        return self.status()

    def resume(self) -> dict[str, Any]:
        with self._lock:
            if self._state != "paused":
                raise RuntimeError("Capture is not paused.")
            self._paused_event.clear()
            self._state = "running"
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        with self._lock:
            capture = self._capture
            if self._state in {"running", "paused"}:
                self._state = "stopping"
        if capture:
            capture.stop()
        return self.status()

    def shutdown(self, timeout_seconds: float = 3.0) -> None:
        self.stop()
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout_seconds)

    def status(self) -> dict[str, Any]:
        with self._lock:
            elapsed = 0.0 if self._started_at is None else max(monotonic() - self._started_at, 0.0)
            return {
                "state": self._state,
                "interface": self._options.interface or "Default interface",
                "filterExpression": self._options.filter_expression,
                "savePackets": self._options.save_packets,
                "detectionEnabled": self._options.detection_enabled,
                "packetTotal": self._packet_total,
                "alertTotal": self._alert_total,
                "skippedTotal": self._skipped_total,
                "savedPacketTotal": self._saved_packet_total,
                "savedAlertTotal": self._saved_alert_total,
                "packetsPerSecond": round(self._packet_total / elapsed, 2) if elapsed else 0.0,
                "error": self._error,
                "nextSequence": self._sequence,
            }

    def reset_statistics(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Stop live capture before resetting statistics.")
            self._state = "stopped"
            self._error = ""
            self._started_at = None
            self._options = CaptureStartOptions()
            self._packet_total = 0
            self._alert_total = 0
            self._skipped_total = 0
            self._saved_packet_total = 0
            self._saved_alert_total = 0
            self._sequence = 0
            self._recent_packets.clear()
            self._recent_alerts.clear()

    def packets_since(self, sequence: int, limit: int = 250) -> dict[str, Any]:
        with self._lock:
            records = [record for record in self._recent_packets if int(record["sequence"]) > sequence]
            return {"records": records[:max(1, min(limit, 500))], "nextSequence": self._sequence}

    def alerts_since(self, sequence: int, limit: int = 100) -> dict[str, Any]:
        with self._lock:
            records = [record for record in self._recent_alerts if int(record["sequence"]) > sequence]
            return {"records": records[:max(1, min(limit, 250))], "nextSequence": self._sequence}

    def topology_connections(self) -> list[dict[str, object]]:
        """Aggregate the in-memory capture window when packet persistence is disabled."""
        with self._lock:
            records = list(self._recent_packets)
        aggregated: dict[tuple[str, str, str], dict[str, object]] = {}
        for record in records:
            details = record.get("details")
            if not isinstance(details, dict):
                continue
            source = str(details.get("src_ip") or "")
            target = str(details.get("dst_ip") or "")
            if not source or not target or source == target:
                continue
            protocol = str(details.get("protocol") or "UNKNOWN")
            key = (source, target, protocol)
            item = aggregated.setdefault(
                key,
                {"source": source, "target": target, "protocol": protocol, "packets": 0, "bytes": 0, "last_seen": ""},
            )
            item["packets"] = int(item["packets"]) + 1
            item["bytes"] = int(item["bytes"]) + int(details.get("length") or 0)
            item["last_seen"] = max(str(item["last_seen"]), str(details.get("timestamp") or ""))
        return sorted(aggregated.values(), key=lambda item: (int(item["packets"]), str(item["last_seen"])), reverse=True)

    def _run(self) -> None:
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        last_flush = monotonic()
        parser = PacketParser()

        try:
            rules = RuleRepository(self.database).list_all()
            custom_rules = CustomRuleRepository(self.database).list_all()
            engine = DetectionEngine.from_rule_records(
                rules,
                custom_rules,
                alert_cooldown_seconds=self._options.alert_cooldown_seconds,
                asset_importance=AssetRepository(self.database).importance_map(),
                blocklist_entries=BlocklistEntryRepository(self.database).list_all(enabled_only=True),
            )
            traffic_repository = TrafficRepository(self.database)

            def flush(force: bool = False) -> None:
                nonlocal last_flush
                now = monotonic()
                if not packet_batch and not alert_batch:
                    return
                if not force and len(packet_batch) < 50 and now - last_flush < 0.5:
                    return
                packets_to_save = packet_batch if self._options.save_packets else []
                saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                with self._lock:
                    self._saved_packet_total += saved_packets
                    self._saved_alert_total += saved_alerts
                    for packet in packet_batch:
                        self._append_packet(packet)
                    for alert in alert_batch:
                        self._append_alert(alert)
                packet_batch.clear()
                alert_batch.clear()
                last_flush = now

            def handle_raw_packet(raw_packet: object) -> None:
                if self._stop_event.is_set() or self._paused_event.is_set():
                    return
                try:
                    packet = parser.parse(raw_packet)
                    alerts = engine.process_packet(packet) if self._options.detection_enabled else []
                except Exception:
                    with self._lock:
                        self._skipped_total += 1
                    return
                with self._lock:
                    self._packet_total += 1
                    self._alert_total += len(alerts)
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                flush()

            self._capture = LiveCapture(
                interface=self._options.interface,
                packet_callback=handle_raw_packet,
                idle_callback=lambda: flush(force=True),
                capture_filter=PacketFilter.compile(self._options.filter_expression).capture_filter or None,
            )
            if self._stop_event.is_set():
                return
            self._capture.start()
        except Exception as exc:
            with self._lock:
                self._error = str(exc)
                self._state = "error"
        finally:
            if "flush" in locals():
                try:
                    flush(force=True)
                except Exception as exc:
                    with self._lock:
                        self._error = str(exc)
                        self._state = "error"
            with self._lock:
                self._capture = None
                if self._state != "error":
                    self._state = "stopped"

    def _append_packet(self, packet: PacketRecord) -> None:
        self._sequence += 1
        source = _endpoint(packet.src_ip, packet.src_port)
        destination = _endpoint(packet.dst_ip, packet.dst_port)
        self._recent_packets.append(
            {
                "sequence": self._sequence,
                "id": packet.id or self._sequence,
                "timestamp": packet.timestamp,
                "source": source,
                "destination": destination,
                "protocol": packet.protocol,
                "length": packet.length,
                "flags": packet.tcp_flags or "",
                "summary": packet.raw_summary,
                "details": asdict(packet),
            }
        )

    def _append_alert(self, alert: AlertRecord) -> None:
        self._sequence += 1
        self._recent_alerts.append(
            {
                "sequence": self._sequence,
                "id": alert.id or self._sequence,
                "timestamp": alert.timestamp,
                "ruleId": alert.rule_id,
                "ruleName": alert.rule_name,
                "severity": alert.severity,
                "source": _endpoint(alert.src_ip, alert.src_port),
                "destination": _endpoint(alert.dst_ip, alert.dst_port),
                "protocol": alert.protocol or "UNKNOWN",
                "description": alert.description,
                "evidence": alert.evidence,
            }
        )


def default_capture_options(database: Database) -> CaptureStartOptions:
    settings = SettingsRepository(database)
    return CaptureStartOptions(
        save_packets=settings.get_bool("auto_save_packets", True),
        detection_enabled=settings.get_bool("enable_realtime_detection", True),
        alert_cooldown_seconds=max(0, settings.get_int("alert_cooldown_seconds", 10)),
    )


def parse_capture_options(payload: dict[str, Any], defaults: CaptureStartOptions) -> CaptureStartOptions:
    interface = payload.get("interface", defaults.interface)
    if interface is not None and not isinstance(interface, str):
        raise ValueError("interface must be a string or null")
    expression = payload.get("filterExpression", defaults.filter_expression)
    if not isinstance(expression, str):
        raise ValueError("filterExpression must be a string")
    save_packets = payload.get("savePackets", defaults.save_packets)
    detection_enabled = payload.get("detectionEnabled", defaults.detection_enabled)
    cooldown = payload.get("alertCooldownSeconds", defaults.alert_cooldown_seconds)
    if not isinstance(save_packets, bool) or not isinstance(detection_enabled, bool):
        raise ValueError("savePackets and detectionEnabled must be booleans")
    if not isinstance(cooldown, int):
        raise ValueError("alertCooldownSeconds must be an integer")
    try:
        PacketFilter.compile(expression)
    except PacketFilterError as exc:
        raise ValueError(str(exc)) from exc
    return CaptureStartOptions(interface, expression, save_packets, detection_enabled, max(0, cooldown))


def _endpoint(ip: str | None, port: int | None) -> str:
    if not ip:
        return "-"
    return f"{ip}:{port}" if port is not None else ip
