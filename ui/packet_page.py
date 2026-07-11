from __future__ import annotations

from time import monotonic
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.constants import PROJECT_ROOT
from capture.decrypted_http_loader import DecryptedHttpLoader
from capture.interface_manager import InterfaceManager
from capture.live_capture import LiveCapture
from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from models import AlertRecord, CustomRuleRecord, PacketRecord, RuleRecord
from parser.decrypted_http_parser import DecryptedHttpParser
from parser.packet_parser import PacketParser
from storage.database import Database
from storage.repositories import (
    AlertRepository,
    CustomRuleRepository,
    PacketRepository,
    RuleRepository,
    SettingsRepository,
)
from ui.widgets.packet_table import PacketTable


class PcapImportWorker(QThread):
    batch_processed = Signal(list, list)
    import_failed = Signal(str)
    import_finished = Signal(int, int)

    def __init__(
        self,
        pcap_path: str | Path,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        batch_size: int = 100,
    ) -> None:
        super().__init__()
        self.pcap_path = Path(pcap_path)
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.batch_size = batch_size

    def run(self) -> None:
        loader = PcapLoader()
        parser = PacketParser()
        engine = DetectionEngine.from_rule_records(self.rule_records, self.custom_rule_records, alert_cooldown_seconds=10)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        packet_total = 0
        alert_total = 0

        try:
            for raw_packet in loader.load(self.pcap_path):
                packet = parser.parse(raw_packet)
                alerts = engine.process_packet(packet)
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                packet_total += 1
                alert_total += len(alerts)

                if len(packet_batch) >= self.batch_size:
                    self.batch_processed.emit(packet_batch, alert_batch)
                    packet_batch = []
                    alert_batch = []

            if packet_batch or alert_batch:
                self.batch_processed.emit(packet_batch, alert_batch)
            self.import_finished.emit(packet_total, alert_total)
        except Exception as exc:
            self.import_failed.emit(str(exc))


class DecryptedHttpImportWorker(QThread):
    batch_processed = Signal(list, list)
    import_failed = Signal(str)
    import_finished = Signal(int, int)

    def __init__(
        self,
        log_path: str | Path,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        batch_size: int = 100,
    ) -> None:
        super().__init__()
        self.log_path = Path(log_path)
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.batch_size = batch_size

    def run(self) -> None:
        loader = DecryptedHttpLoader()
        parser = DecryptedHttpParser()
        engine = DetectionEngine.from_rule_records(self.rule_records, self.custom_rule_records, alert_cooldown_seconds=10)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        packet_total = 0
        alert_total = 0

        try:
            for decrypted_record in loader.load(self.log_path):
                packet = parser.parse(decrypted_record)
                alerts = engine.process_packet(packet)
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                packet_total += 1
                alert_total += len(alerts)

                if len(packet_batch) >= self.batch_size:
                    self.batch_processed.emit(packet_batch, alert_batch)
                    packet_batch = []
                    alert_batch = []

            if packet_batch or alert_batch:
                self.batch_processed.emit(packet_batch, alert_batch)
            self.import_finished.emit(packet_total, alert_total)
        except Exception as exc:
            self.import_failed.emit(str(exc))


class LiveCaptureWorker(QThread):
    packet_processed = Signal(list, list)
    capture_failed = Signal(str)
    capture_stopped = Signal()

    def __init__(
        self,
        interface: str | None,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        batch_size: int = 50,
        flush_interval_seconds: float = 0.5,
        capture_filter: str | None = None,
    ) -> None:
        super().__init__()
        self.interface = interface
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.capture_filter = capture_filter
        self.parser = PacketParser()
        self.capture: LiveCapture | None = None

    def run(self) -> None:
        engine = DetectionEngine.from_rule_records(self.rule_records, self.custom_rule_records, alert_cooldown_seconds=10)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        last_flush = monotonic()

        def flush_batch(force: bool = False) -> None:
            nonlocal last_flush
            if not packet_batch and not alert_batch:
                return
            if not force and len(packet_batch) < self.batch_size and monotonic() - last_flush < self.flush_interval_seconds:
                return
            self.packet_processed.emit(packet_batch.copy(), alert_batch.copy())
            packet_batch.clear()
            alert_batch.clear()
            last_flush = monotonic()

        def handle_raw_packet(raw_packet: object) -> None:
            try:
                packet = self.parser.parse(raw_packet)
                alerts = engine.process_packet(packet)
            except Exception:
                return
            packet_batch.append(packet)
            alert_batch.extend(alerts)
            flush_batch()

        self.capture = LiveCapture(
            interface=self.interface,
            packet_callback=handle_raw_packet,
            idle_callback=lambda: flush_batch(force=True),
            capture_filter=self.capture_filter,
        )
        try:
            self.capture.start()
        except Exception as exc:
            self.capture_failed.emit(str(exc))
        finally:
            flush_batch(force=True)
            self.capture_stopped.emit()

    def stop_capture(self) -> None:
        if self.capture:
            self.capture.stop()


class PacketPage(QWidget):
    CAPTURE_FILTER_PRESETS = {
        "All traffic": "",
        "Web + DNS": "tcp port 80 or tcp port 443 or udp port 53 or tcp port 53",
        "Internal TCP/UDP": "ip and (tcp or udp) and (net 10.0.0.0/8 or net 172.16.0.0/12 or net 192.168.0.0/16)",
        "Custom": "",
    }

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.rule_repository = RuleRepository(database)
        self.custom_rule_repository = CustomRuleRepository(database)
        self.settings_repository = SettingsRepository(database)
        self.interface_manager = InterfaceManager()
        self.import_worker: PcapImportWorker | None = None
        self.live_worker: LiveCaptureWorker | None = None
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        toolbar = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.refresh_interfaces_button = QPushButton("Refresh interfaces")
        self.import_button = QPushButton("Import pcap")
        self.demo_button = QPushButton("Load demo data")
        self.import_decrypted_button = QPushButton("Import decrypted HTTP log")
        self.import_decrypted_button.setToolTip(
            "Import authorized decrypted HTTP request logs for payload checks. Raw HTTPS pcaps are analyzed as TLS metadata only."
        )
        self.start_capture_button = QPushButton("Start capture")
        self.stop_capture_button = QPushButton("Stop capture")
        self.clear_button = QPushButton("Clear table")
        self.stop_capture_button.setEnabled(False)

        toolbar.addWidget(self.interface_combo, 1)
        toolbar.addWidget(self.refresh_interfaces_button)
        toolbar.addWidget(self.import_button)
        toolbar.addWidget(self.demo_button)
        toolbar.addWidget(self.import_decrypted_button)
        toolbar.addWidget(self.start_capture_button)
        toolbar.addWidget(self.stop_capture_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addStretch()

        capture_options = QHBoxLayout()
        self.capture_filter_combo = QComboBox()
        self.capture_filter_combo.addItems(self.CAPTURE_FILTER_PRESETS.keys())
        self.capture_filter_input = QLineEdit(self.CAPTURE_FILTER_PRESETS["All traffic"])
        self.capture_filter_input.setPlaceholderText("Optional BPF capture filter")
        self.capture_filter_input.setReadOnly(True)
        self.capture_filter_input.setToolTip("Use a BPF filter to reduce live-capture volume before packets reach the parser.")
        self.visible_rows_box = QSpinBox()
        self.visible_rows_box.setRange(100, 20_000)
        self.visible_rows_box.setSingleStep(100)
        self.visible_rows_box.setValue(PacketTable.MAX_VISIBLE_ROWS)
        self.visible_rows_box.setSuffix(" visible rows")
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.setToolTip("Keep the packet table pinned to the newest packet while capture or import is running.")
        capture_options.addWidget(QLabel("Capture filter"))
        capture_options.addWidget(self.capture_filter_combo)
        capture_options.addWidget(self.capture_filter_input, 1)
        capture_options.addWidget(QLabel("Table window"))
        capture_options.addWidget(self.visible_rows_box)
        capture_options.addWidget(self.auto_scroll_check)

        self.status_label = QLabel("Import a local pcap file for offline analysis, or choose a network interface for live capture.")
        self.status_label.setObjectName("PageHint")
        self.status_label.setWordWrap(True)
        self.packet_table = PacketTable()

        layout.addLayout(toolbar, 0)
        layout.addLayout(capture_options, 0)
        layout.addWidget(self.status_label)
        layout.addWidget(self.packet_table, 1)

        self.import_button.clicked.connect(self.select_pcap_file)
        self.demo_button.clicked.connect(self.load_demo_data)
        self.import_decrypted_button.clicked.connect(self.select_decrypted_http_log)
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.capture_filter_combo.currentTextChanged.connect(self.update_capture_filter_mode)
        self.visible_rows_box.valueChanged.connect(self.packet_table.set_max_visible_rows)
        self.auto_scroll_check.toggled.connect(self.packet_table.set_auto_scroll)
        self.start_capture_button.clicked.connect(self.start_live_capture)
        self.stop_capture_button.clicked.connect(self.stop_live_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.refresh_interfaces()
        self.update_capture_filter_mode(self.capture_filter_combo.currentText())

    def refresh_interfaces(self) -> None:
        self.interface_combo.clear()
        self.interface_combo.addItem("Default interface", None)
        try:
            for interface in self.interface_manager.list_interfaces():
                self.interface_combo.addItem(interface, interface)
            self.status_label.setText("Interface list refreshed. Live capture on Windows may require Npcap and administrator privileges.")
        except Exception as exc:
            self.status_label.setText(f"Failed to load network interfaces: {exc}")

    def select_pcap_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select pcap file",
            self._default_pcap_dialog_location(),
            "pcap files (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if path:
            self.start_import(path)

    def load_demo_data(self) -> None:
        demo_path = PROJECT_ROOT / "sample_data" / "demo_attack_chain.pcap"
        if not demo_path.exists():
            try:
                from scripts.generate_demo_pcap import generate_demo_pcap

                generate_demo_pcap(demo_path)
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Demo data unavailable",
                    f"Could not create the demo pcap at {demo_path}.\n\n{exc}",
                )
                return
        self.start_import(demo_path)

    def start_import(self, path: str | Path) -> None:
        if self.import_worker and self.import_worker.isRunning():
            QMessageBox.information(self, "Import in progress", "A pcap file is already being imported. Please wait.")
            return

        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.packet_table.clear_packets()
        self._set_busy(True)
        self.status_label.setText(f"Importing and detecting: {Path(path).name}")

        self.import_worker = PcapImportWorker(
            path,
            self.rule_repository.list_all(),
            self.custom_rule_repository.list_all(),
        )
        self.import_worker.batch_processed.connect(self.handle_processed_batch)
        self.import_worker.import_failed.connect(self.handle_import_failed)
        self.import_worker.import_finished.connect(self.handle_import_finished)
        self.import_worker.start()

    def select_decrypted_http_log(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select decrypted HTTP log",
            "",
            "Decrypted HTTP logs (*.jsonl *.csv);;All files (*)",
        )
        if path:
            self.start_decrypted_http_import(path)

    def start_decrypted_http_import(self, path: str | Path) -> None:
        if self.import_worker and self.import_worker.isRunning():
            QMessageBox.information(self, "Import in progress", "A traffic file is already being imported. Please wait.")
            return

        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.packet_table.clear_packets()
        self._set_busy(True)
        self.status_label.setText(f"Importing authorized decrypted HTTP log: {Path(path).name}")

        self.import_worker = DecryptedHttpImportWorker(
            path,
            self.rule_repository.list_all(),
            self.custom_rule_repository.list_all(),
        )
        self.import_worker.batch_processed.connect(self.handle_processed_batch)
        self.import_worker.import_failed.connect(self.handle_import_failed)
        self.import_worker.import_finished.connect(self.handle_import_finished)
        self.import_worker.start()

    def start_live_capture(self) -> None:
        if self.live_worker and self.live_worker.isRunning():
            return
        interface = self.interface_combo.currentData()
        capture_filter = self.capture_filter_input.text().strip() or None
        filter_label = capture_filter or "none"
        self.status_label.setText(f"Live capture started. Capture filter: {filter_label}. Packets and alerts will be written to the database.")
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)
        self.import_button.setEnabled(False)
        self.demo_button.setEnabled(False)
        self.import_decrypted_button.setEnabled(False)
        self.refresh_interfaces_button.setEnabled(False)
        self.capture_filter_combo.setEnabled(False)
        self.capture_filter_input.setEnabled(False)

        self.live_worker = LiveCaptureWorker(
            interface=interface,
            rule_records=self.rule_repository.list_all(),
            custom_rule_records=self.custom_rule_repository.list_all(),
            capture_filter=capture_filter,
        )
        self.live_worker.packet_processed.connect(self.handle_processed_batch)
        self.live_worker.capture_failed.connect(self.handle_capture_failed)
        self.live_worker.capture_stopped.connect(self.handle_capture_stopped)
        self.live_worker.start()

    def stop_live_capture(self) -> None:
        if self.live_worker and self.live_worker.isRunning():
            self.status_label.setText("Stopping live capture...")
            self.live_worker.stop_capture()

    def handle_processed_batch(self, packets: list[PacketRecord], alerts: list[AlertRecord]) -> None:
        self.loaded_count += len(packets)
        self.packet_table.add_packets(packets)
        self.saved_packet_count += self.packet_repository.add_many(packets)
        self.saved_alert_count += self.alert_repository.add_many(alerts)
        self.status_label.setText(
            f"Processed {self.loaded_count} packets, saved {self.saved_packet_count} packet records, "
            f"and generated {self.saved_alert_count} alerts."
        )

    def handle_import_failed(self, message: str) -> None:
        self._set_busy(False)
        self.status_label.setText("pcap import failed.")
        QMessageBox.critical(self, "Import failed", message)

    def handle_import_finished(self, packet_total: int, alert_total: int) -> None:
        self._set_busy(False)
        self.status_label.setText(f"Import complete: parsed {packet_total} packets and generated {alert_total} alerts.")

    def handle_capture_failed(self, message: str) -> None:
        self.status_label.setText("Live capture failed.")
        QMessageBox.critical(
            self,
            "Live capture failed",
            f"{message}\n\nOn Windows, confirm that Npcap is installed and try running with administrator privileges.",
        )

    def handle_capture_stopped(self) -> None:
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)
        self.import_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.import_decrypted_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)
        self.capture_filter_combo.setEnabled(True)
        self.capture_filter_input.setEnabled(True)
        if "failed" not in self.status_label.text().lower():
            self.status_label.setText("Live capture stopped.")

    def clear_packets(self) -> None:
        self.packet_table.clear_packets()
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.status_label.setText("Table cleared. You can import a pcap file or start live capture again.")

    def _set_busy(self, busy: bool) -> None:
        self.import_button.setEnabled(not busy)
        self.demo_button.setEnabled(not busy)
        self.import_decrypted_button.setEnabled(not busy)
        self.clear_button.setEnabled(not busy)
        self.start_capture_button.setEnabled(not busy)
        self.refresh_interfaces_button.setEnabled(not busy)
        self.capture_filter_combo.setEnabled(not busy)
        self.capture_filter_input.setEnabled(not busy)

    def update_capture_filter_mode(self, mode: str) -> None:
        preset = self.CAPTURE_FILTER_PRESETS.get(mode, "")
        self.capture_filter_input.setReadOnly(mode != "Custom")
        if mode != "Custom":
            self.capture_filter_input.setText(preset)
        self.capture_filter_input.setPlaceholderText("Type a BPF capture filter" if mode == "Custom" else "No capture filter")

    def _default_pcap_dialog_location(self) -> str:
        configured_path = self.settings_repository.get("default_pcap_path", "").strip()
        if not configured_path:
            return ""
        path = Path(configured_path)
        if path.is_file():
            return str(path.parent)
        if path.is_dir():
            return str(path)
        if path.parent.exists():
            return str(path.parent)
        return ""
