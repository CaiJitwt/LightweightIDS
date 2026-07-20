from __future__ import annotations

from pathlib import Path
from threading import RLock, Thread
from typing import Any, Callable

from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from models import AlertRecord, PacketRecord
from parser.packet_parser import PacketParser
from storage.analyst_repositories import AssetRepository
from storage.blocklist_repository import BlocklistEntryRepository
from storage.database import Database
from storage.repositories import CustomRuleRepository, RuleRepository, SettingsRepository, TrafficRepository


class PcapImportService:
    """Background PCAP import for the local React prototype API."""

    ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

    def __init__(
        self,
        database: Database,
        activity_callback: Callable[
            [list[PacketRecord], list[AlertRecord], int, int],
            None,
        ] | None = None,
    ) -> None:
        self.database = database
        self.activity_callback = activity_callback
        self._lock = RLock()
        self._thread: Thread | None = None
        self._state = "idle"
        self._filename = ""
        self._packet_total = 0
        self._alert_total = 0
        self._skipped_total = 0
        self._saved_packet_total = 0
        self._saved_alert_total = 0
        self._error = ""

    def start(self, path: Path, *, filename: str | None = None, remove_after: bool = False) -> dict[str, Any]:
        pcap_path = path.resolve()
        if pcap_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError("Only .pcap, .pcapng, and .cap files can be imported.")
        if not pcap_path.is_file():
            raise ValueError("The selected PCAP file could not be found.")
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("A PCAP import is already running.")
            self._state = "importing"
            self._filename = filename or pcap_path.name
            self._packet_total = 0
            self._alert_total = 0
            self._skipped_total = 0
            self._saved_packet_total = 0
            self._saved_alert_total = 0
            self._error = ""
            self._thread = Thread(
                target=self._run,
                args=(pcap_path, remove_after),
                name="modern-ids-pcap-import",
                daemon=True,
            )
            self._thread.start()
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state,
                "filename": self._filename,
                "packetTotal": self._packet_total,
                "alertTotal": self._alert_total,
                "skippedTotal": self._skipped_total,
                "savedPacketTotal": self._saved_packet_total,
                "savedAlertTotal": self._saved_alert_total,
                "error": self._error,
            }

    def shutdown(self, timeout_seconds: float = 3.0) -> None:
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout_seconds)

    def reset_statistics(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Wait for the PCAP import to finish before resetting statistics.")
            self._state = "idle"
            self._filename = ""
            self._packet_total = 0
            self._alert_total = 0
            self._skipped_total = 0
            self._saved_packet_total = 0
            self._saved_alert_total = 0
            self._error = ""

    def _run(self, pcap_path: Path, remove_after: bool) -> None:
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        try:
            settings = SettingsRepository(self.database)
            engine = DetectionEngine.from_rule_records(
                RuleRepository(self.database).list_all(),
                CustomRuleRepository(self.database).list_all(),
                alert_cooldown_seconds=max(0, settings.get_int("alert_cooldown_seconds", 10)),
                asset_importance=AssetRepository(self.database).importance_map(),
                blocklist_entries=BlocklistEntryRepository(self.database).list_all(enabled_only=True),
            )
            save_packets = settings.get_bool("auto_save_packets", True)
            repository = TrafficRepository(self.database)

            def flush() -> None:
                if not packet_batch and not alert_batch:
                    return
                packets_to_save = packet_batch if save_packets else []
                saved_packets, saved_alerts = repository.add_batch(packets_to_save, alert_batch)
                published_packets = list(packet_batch)
                published_alerts = list(alert_batch)
                with self._lock:
                    self._saved_packet_total += saved_packets
                    self._saved_alert_total += saved_alerts
                if self.activity_callback is not None:
                    self.activity_callback(
                        published_packets,
                        published_alerts,
                        saved_packets,
                        saved_alerts,
                    )
                packet_batch.clear()
                alert_batch.clear()

            parser = PacketParser()
            for raw_packet in PcapLoader().load(pcap_path):
                try:
                    packet = parser.parse(raw_packet)
                    alerts = engine.process_packet(packet)
                except Exception:
                    with self._lock:
                        self._skipped_total += 1
                    continue
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                with self._lock:
                    self._packet_total += 1
                    self._alert_total += len(alerts)
                if len(packet_batch) >= 100:
                    flush()
            flush()
            with self._lock:
                self._state = "completed"
        except Exception as exc:
            with self._lock:
                self._state = "error"
                self._error = str(exc)
        finally:
            if remove_after:
                try:
                    pcap_path.unlink(missing_ok=True)
                except OSError:
                    pass
