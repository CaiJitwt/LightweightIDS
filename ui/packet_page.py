from __future__ import annotations

from time import monotonic
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Signal
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
from capture.packet_filter import PacketFilter, PacketFilterError
from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from models import AlertRecord, CustomRuleRecord, PacketRecord, RuleRecord
from parser.decrypted_http_parser import DecryptedHttpParser
from parser.packet_parser import PacketParser
from storage.database import Database
from storage.analyst_repositories import AssetRepository
from storage.blocklist_repository import BlocklistEntryRepository
from storage.repositories import (
    CustomRuleRepository,
    RuleRepository,
    SettingsRepository,
    TrafficRepository,
)
from ui.i18n import locale_manager
from ui.widgets.packet_table import PacketTable


class PcapImportWorker(QThread):
    batch_processed = Signal(list, list, int, int)
    import_failed = Signal(str)
    import_finished = Signal(int, int, int)

    def __init__(
        self,
        pcap_path: str | Path,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        database: Database,
        batch_size: int = 100,
        save_packets: bool = True,
        alert_cooldown_seconds: int = 10,
    ) -> None:
        super().__init__()
        self.pcap_path = Path(pcap_path)
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.database = database
        self.batch_size = batch_size
        self.save_packets = save_packets
        self.alert_cooldown_seconds = alert_cooldown_seconds

    def run(self) -> None:
        loader = PcapLoader()
        parser = PacketParser()
        engine = DetectionEngine.from_rule_records(
            self.rule_records,
            self.custom_rule_records,
            alert_cooldown_seconds=self.alert_cooldown_seconds,
            asset_importance=AssetRepository(self.database).importance_map(),
            blocklist_entries=BlocklistEntryRepository(self.database).list_all(enabled_only=True),
        )
        traffic_repository = TrafficRepository(self.database)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        packet_total = 0
        alert_total = 0
        skipped_total = 0

        try:
            for raw_packet in loader.load(self.pcap_path):
                if self.isInterruptionRequested():
                    break
                try:
                    packet = parser.parse(raw_packet)
                    alerts = engine.process_packet(packet)
                except Exception:
                    skipped_total += 1
                    continue
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                packet_total += 1
                alert_total += len(alerts)

                if len(packet_batch) >= self.batch_size:
                    packets_to_save = packet_batch if self.save_packets else []
                    saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                    self.batch_processed.emit(packet_batch, alert_batch, saved_packets, saved_alerts)
                    packet_batch = []
                    alert_batch = []

            if packet_batch or alert_batch:
                packets_to_save = packet_batch if self.save_packets else []
                saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                self.batch_processed.emit(packet_batch, alert_batch, saved_packets, saved_alerts)
            self.import_finished.emit(packet_total, alert_total, skipped_total)
        except Exception as exc:
            self.import_failed.emit(str(exc))


class DecryptedHttpImportWorker(QThread):
    batch_processed = Signal(list, list, int, int)
    import_failed = Signal(str)
    import_finished = Signal(int, int, int)

    def __init__(
        self,
        log_path: str | Path,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        database: Database,
        batch_size: int = 100,
        save_packets: bool = True,
        alert_cooldown_seconds: int = 10,
    ) -> None:
        super().__init__()
        self.log_path = Path(log_path)
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.database = database
        self.batch_size = batch_size
        self.save_packets = save_packets
        self.alert_cooldown_seconds = alert_cooldown_seconds

    def run(self) -> None:
        loader = DecryptedHttpLoader()
        parser = DecryptedHttpParser()
        engine = DetectionEngine.from_rule_records(
            self.rule_records,
            self.custom_rule_records,
            alert_cooldown_seconds=self.alert_cooldown_seconds,
            asset_importance=AssetRepository(self.database).importance_map(),
            blocklist_entries=BlocklistEntryRepository(self.database).list_all(enabled_only=True),
        )
        traffic_repository = TrafficRepository(self.database)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        packet_total = 0
        alert_total = 0
        skipped_total = 0

        try:
            for decrypted_record in loader.load(self.log_path):
                if self.isInterruptionRequested():
                    break
                try:
                    packet = parser.parse(decrypted_record)
                    alerts = engine.process_packet(packet)
                except Exception:
                    skipped_total += 1
                    continue
                packet_batch.append(packet)
                alert_batch.extend(alerts)
                packet_total += 1
                alert_total += len(alerts)

                if len(packet_batch) >= self.batch_size:
                    packets_to_save = packet_batch if self.save_packets else []
                    saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                    self.batch_processed.emit(packet_batch, alert_batch, saved_packets, saved_alerts)
                    packet_batch = []
                    alert_batch = []

            if packet_batch or alert_batch:
                packets_to_save = packet_batch if self.save_packets else []
                saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                self.batch_processed.emit(packet_batch, alert_batch, saved_packets, saved_alerts)
            self.import_finished.emit(packet_total, alert_total, skipped_total)
        except Exception as exc:
            self.import_failed.emit(str(exc))


class LiveCaptureWorker(QThread):
    packet_processed = Signal(list, list, int, int)
    capture_progress = Signal(int, int, float)
    capture_failed = Signal(str)
    capture_stopped = Signal()

    def __init__(
        self,
        interface: str | None,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
        database: Database,
        batch_size: int = 50,
        flush_interval_seconds: float = 0.5,
        capture_filter: str | None = None,
        save_packets: bool = True,
        detection_enabled: bool = True,
        alert_cooldown_seconds: int = 10,
    ) -> None:
        super().__init__()
        self.interface = interface
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.database = database
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.capture_filter = capture_filter
        self.save_packets = save_packets
        self.detection_enabled = detection_enabled
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.parser = PacketParser()
        self.capture: LiveCapture | None = None

    def run(self) -> None:
        engine = DetectionEngine.from_rule_records(
            self.rule_records,
            self.custom_rule_records,
            alert_cooldown_seconds=self.alert_cooldown_seconds,
            asset_importance=AssetRepository(self.database).importance_map(),
            blocklist_entries=BlocklistEntryRepository(self.database).list_all(enabled_only=True),
        )
        traffic_repository = TrafficRepository(self.database)
        packet_batch: list[PacketRecord] = []
        alert_batch: list[AlertRecord] = []
        last_flush = monotonic()
        started_at = last_flush
        packet_total = 0
        skipped_total = 0

        def flush_batch(force: bool = False) -> None:
            nonlocal last_flush
            now = monotonic()
            if packet_batch or alert_batch:
                if not force and len(packet_batch) < self.batch_size and now - last_flush < self.flush_interval_seconds:
                    return
                packets_to_save = packet_batch if self.save_packets else []
                saved_packets, saved_alerts = traffic_repository.add_batch(packets_to_save, alert_batch)
                self.packet_processed.emit(packet_batch.copy(), alert_batch.copy(), saved_packets, saved_alerts)
                packet_batch.clear()
                alert_batch.clear()
                last_flush = now
            if force:
                elapsed = max(now - started_at, 0.001)
                self.capture_progress.emit(packet_total, skipped_total, packet_total / elapsed)

        def handle_raw_packet(raw_packet: object) -> None:
            nonlocal packet_total, skipped_total
            try:
                packet = self.parser.parse(raw_packet)
                alerts = engine.process_packet(packet) if self.detection_enabled else []
            except Exception:
                skipped_total += 1
                return
            packet_total += 1
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
            try:
                flush_batch(force=True)
            except Exception as exc:
                self.capture_failed.emit(str(exc))
            finally:
                self.capture_stopped.emit()

    def stop_capture(self) -> None:
        if self.capture:
            self.capture.stop()


class PacketPage(QWidget):
    CAPTURE_FILTER_PRESETS = {
        "All traffic": "",
        "TCP": "tcp",
        "UDP": "udp",
        "DNS": "dns",
        "HTTP": "http",
        "HTTPS / TLS": "https or tls",
        "ICMP": "icmp or icmpv6",
        "ARP": "arp",
        "Web + DNS": "http or https or tls or dns",
        "Internal TCP/UDP": (
            "(tcp or udp) and (ip.addr == 10.0.0.0/8 or ip.addr == 172.16.0.0/12 "
            "or ip.addr == 192.168.0.0/16)"
        ),
        "Custom": "",
    }

    def __init__(self, database: Database) -> None:
        super().__init__()
        self._lm = locale_manager()
        self._retranslating = False
        self.database = database
        self.rule_repository = RuleRepository(database)
        self.custom_rule_repository = CustomRuleRepository(database)
        self.settings_repository = SettingsRepository(database)
        self.interface_manager = InterfaceManager()
        self.import_worker: PcapImportWorker | None = None
        self.live_worker: LiveCaptureWorker | None = None
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.capture_skipped_count = 0
        self.capture_rate = 0.0
        self.capture_failed_flag = False
        self.packet_filter = PacketFilter.compile("")
        self.active_capture_filter = ""
        self.custom_filter_text = ""
        self._filter_mode = "All traffic"
        self.filter_error_message = ""
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(250)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        toolbar = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.refresh_interfaces_button = QPushButton(self._lm.tr("page.packets.refresh_interfaces"))
        self.import_button = QPushButton(self._lm.tr("page.packets.import_pcap"))
        self.demo_button = QPushButton(self._lm.tr("page.packets.load_demo"))
        self.import_decrypted_button = QPushButton(self._lm.tr("page.packets.import_decrypted_http"))
        self.import_decrypted_button.setToolTip(self._lm.tr("page.packets.decrypted_tooltip"))
        self.start_capture_button = QPushButton(self._lm.tr("page.packets.start_capture"))
        self.stop_capture_button = QPushButton(self._lm.tr("page.packets.stop_capture"))
        self.clear_button = QPushButton(self._lm.tr("page.packets.clear_table"))
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

        self._CAPTURE_FILTER_I18N = {
            "All traffic": "page.packets.filter_all_traffic",
            "Web + DNS": "page.packets.filter_web_dns",
            "Internal TCP/UDP": "page.packets.filter_internal_tcp_udp",
            "Custom": "page.packets.filter_custom",
        }

        capture_options = QHBoxLayout()
        self.capture_filter_combo = QComboBox()
        for english_key in self.CAPTURE_FILTER_PRESETS:
            i18n_key = self._CAPTURE_FILTER_I18N.get(english_key, english_key)
            self.capture_filter_combo.addItem(self._lm.tr(i18n_key), english_key)
        self.capture_filter_input = QLineEdit(self.CAPTURE_FILTER_PRESETS["All traffic"])
        self.capture_filter_input.setPlaceholderText(self._lm.tr("page.packets.filter_placeholder"))
        self.capture_filter_input.setReadOnly(True)
        self.capture_filter_input.setToolTip(self._lm.tr("page.packets.bpf_tooltip"))
        self.filter_result_label = QLabel()
        self.filter_result_label.setObjectName("PageHint")
        self.visible_rows_box = QSpinBox()
        self.visible_rows_box.setRange(100, 20_000)
        self.visible_rows_box.setSingleStep(100)
        self.visible_rows_box.setValue(PacketTable.MAX_VISIBLE_ROWS)
        self.visible_rows_box.setSuffix(" " + self._lm.tr("page.packets.visible_rows_suffix"))
        self.auto_scroll_check = QCheckBox(self._lm.tr("page.packets.auto_scroll"))
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.setToolTip(self._lm.tr("page.packets.auto_scroll_tooltip"))
        self.capture_filter_label = QLabel(self._lm.tr("page.packets.capture_filter"))
        self.table_window_label = QLabel(self._lm.tr("page.packets.table_window"))
        capture_options.addWidget(self.capture_filter_label)
        capture_options.addWidget(self.capture_filter_combo)
        capture_options.addWidget(self.capture_filter_input, 1)
        capture_options.addWidget(self.table_window_label)
        capture_options.addWidget(self.visible_rows_box)
        capture_options.addWidget(self.auto_scroll_check)

        self.status_label = QLabel(self._lm.tr("page.packets.status_initial"))
        self.status_label.setObjectName("PageHint")
        self.status_label.setWordWrap(True)
        self.packet_table = PacketTable()

        layout.addLayout(toolbar, 0)
        layout.addLayout(capture_options, 0)
        layout.addWidget(self.filter_result_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.packet_table, 1)

        self.import_button.clicked.connect(self.select_pcap_file)
        self.demo_button.clicked.connect(self.load_demo_data)
        self.import_decrypted_button.clicked.connect(self.select_decrypted_http_log)
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.capture_filter_combo.currentTextChanged.connect(self.update_capture_filter_mode)
        self.capture_filter_input.textChanged.connect(self.schedule_packet_filter)
        self.capture_filter_input.returnPressed.connect(self.apply_packet_filter)
        self.filter_timer.timeout.connect(self.apply_packet_filter)
        self.visible_rows_box.valueChanged.connect(self.update_visible_row_limit)
        self.auto_scroll_check.toggled.connect(self.packet_table.set_auto_scroll)
        self.start_capture_button.clicked.connect(self.start_live_capture)
        self.stop_capture_button.clicked.connect(self.stop_live_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.refresh_interfaces()
        self.update_capture_filter_mode(self.capture_filter_combo.currentText())

        self._lm.locale_changed.connect(self.retranslate_ui)

    def retranslate_ui(self) -> None:
        self._retranslating = True

        self.refresh_interfaces_button.setText(self._lm.tr("page.packets.refresh_interfaces"))
        self.import_button.setText(self._lm.tr("page.packets.import_pcap"))
        self.demo_button.setText(self._lm.tr("page.packets.load_demo"))
        self.import_decrypted_button.setText(self._lm.tr("page.packets.import_decrypted_http"))
        self.start_capture_button.setText(self._lm.tr("page.packets.start_capture"))
        self.stop_capture_button.setText(self._lm.tr("page.packets.stop_capture"))
        self.clear_button.setText(self._lm.tr("page.packets.clear_table"))

        self.import_decrypted_button.setToolTip(self._lm.tr("page.packets.decrypted_tooltip"))
        self.capture_filter_input.setToolTip(self._lm.tr("page.packets.bpf_tooltip"))
        self.auto_scroll_check.setToolTip(self._lm.tr("page.packets.auto_scroll_tooltip"))

        self.auto_scroll_check.setText(self._lm.tr("page.packets.auto_scroll"))
        self.capture_filter_label.setText(self._lm.tr("page.packets.capture_filter"))
        self.table_window_label.setText(self._lm.tr("page.packets.table_window"))
        self.visible_rows_box.setSuffix(" " + self._lm.tr("page.packets.visible_rows_suffix"))

        for i in range(self.capture_filter_combo.count()):
            english_key = self.capture_filter_combo.itemData(i)
            if english_key and english_key in self._CAPTURE_FILTER_I18N:
                self.capture_filter_combo.setItemText(i, self._lm.tr(self._CAPTURE_FILTER_I18N[english_key]))

        if self.interface_combo.count() > 0:
            self.interface_combo.setItemText(0, self._lm.tr("page.packets.default_interface"))

        self._retranslating = False

    def refresh_interfaces(self) -> None:
        self.interface_combo.clear()
        self.interface_combo.addItem(self._lm.tr("page.packets.default_interface"), None)
        try:
            for interface in self.interface_manager.list_interfaces():
                self.interface_combo.addItem(interface, interface)
            self.status_label.setText(self._lm.tr("page.packets.status_interfaces_ok"))
        except Exception as exc:
            self.status_label.setText(self._lm.tr("page.packets.status_interfaces_failed", exc=exc))

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
        self.status_label.setText(self._lm.tr("page.packets.status_importing", filename=Path(path).name))
        save_packets = self.settings_repository.get_bool("auto_save_packets", True)
        alert_cooldown = max(0, self.settings_repository.get_int("alert_cooldown_seconds", 10))

        self.import_worker = PcapImportWorker(
            path,
            self.rule_repository.list_all(),
            self.custom_rule_repository.list_all(),
            self.database,
            save_packets=save_packets,
            alert_cooldown_seconds=alert_cooldown,
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
        self.status_label.setText(self._lm.tr("page.packets.status_importing_decrypted", filename=Path(path).name))
        save_packets = self.settings_repository.get_bool("auto_save_packets", True)
        alert_cooldown = max(0, self.settings_repository.get_int("alert_cooldown_seconds", 10))

        self.import_worker = DecryptedHttpImportWorker(
            path,
            self.rule_repository.list_all(),
            self.custom_rule_repository.list_all(),
            self.database,
            save_packets=save_packets,
            alert_cooldown_seconds=alert_cooldown,
        )
        self.import_worker.batch_processed.connect(self.handle_processed_batch)
        self.import_worker.import_failed.connect(self.handle_import_failed)
        self.import_worker.import_finished.connect(self.handle_import_finished)
        self.import_worker.start()

    def start_live_capture(self) -> None:
        if self.live_worker and self.live_worker.isRunning():
            return
        self.filter_timer.stop()
        if not self.apply_packet_filter():
            return
        interface = self.interface_combo.currentData()
        capture_filter = self.packet_filter.capture_filter or None
        filter_label = capture_filter or "none"
        save_packets = self.settings_repository.get_bool("auto_save_packets", True)
        detection_enabled = self.settings_repository.get_bool("enable_realtime_detection", True)
        alert_cooldown = max(0, self.settings_repository.get_int("alert_cooldown_seconds", 10))
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.capture_skipped_count = 0
        self.capture_rate = 0.0
        self.capture_failed_flag = False
        self.active_capture_filter = capture_filter or ""
        self.packet_table.clear_packets()
        self._update_filter_status()
        detection_label = self._lm.tr("common.enabled") if detection_enabled else self._lm.tr("common.disabled")
        storage_label = self._lm.tr("common.enabled") if save_packets else self._lm.tr("common.disabled")
        self.status_label.setText(self._lm.tr("page.packets.status_live_started", filter=filter_label, detection=detection_label, storage=storage_label))
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)
        self.import_button.setEnabled(False)
        self.demo_button.setEnabled(False)
        self.import_decrypted_button.setEnabled(False)
        self.refresh_interfaces_button.setEnabled(False)

        self.live_worker = LiveCaptureWorker(
            interface=interface,
            rule_records=self.rule_repository.list_all(),
            custom_rule_records=self.custom_rule_repository.list_all(),
            database=self.database,
            capture_filter=capture_filter,
            save_packets=save_packets,
            detection_enabled=detection_enabled,
            alert_cooldown_seconds=alert_cooldown,
        )
        self.live_worker.packet_processed.connect(self.handle_processed_batch)
        self.live_worker.capture_progress.connect(self.handle_capture_progress)
        self.live_worker.capture_failed.connect(self.handle_capture_failed)
        self.live_worker.capture_stopped.connect(self.handle_capture_stopped)
        self.live_worker.start()

    def stop_live_capture(self) -> None:
        if self.live_worker and self.live_worker.isRunning():
            self.status_label.setText(self._lm.tr("page.packets.status_stopping"))
            self.live_worker.stop_capture()

    def handle_processed_batch(
        self,
        packets: list[PacketRecord],
        alerts: list[AlertRecord],
        saved_packets: int,
        saved_alerts: int,
    ) -> None:
        self.loaded_count += len(packets)
        self.packet_table.add_packets(packets)
        self._update_filter_status()
        self.saved_packet_count += saved_packets
        self.saved_alert_count += saved_alerts
        self.status_label.setText(
            self._lm.tr("page.packets.status_processed", packets=self.loaded_count, saved_packets=self.saved_packet_count, alerts=self.saved_alert_count)
        )

    def handle_import_failed(self, message: str) -> None:
        self._set_busy(False)
        self.status_label.setText(self._lm.tr("page.packets.status_import_failed"))
        QMessageBox.critical(self, self._lm.tr("page.packets.dialog.import_failed_title"), message)

    def handle_import_finished(self, packet_total: int, alert_total: int, skipped_total: int) -> None:
        self._set_busy(False)
        self.status_label.setText(
            self._lm.tr("page.packets.status_import_complete", packets=packet_total, alerts=alert_total, skipped=skipped_total)
        )

    def handle_capture_progress(self, packet_total: int, skipped_total: int, packets_per_second: float) -> None:
        if self.capture_failed_flag:
            return
        self.capture_skipped_count = skipped_total
        self.capture_rate = packets_per_second
        self.status_label.setText(
            f"Live capture: {packet_total} packets processed at {packets_per_second:.1f} packets/s; "
            f"{self.saved_alert_count} alerts saved; {skipped_total} packets skipped."
        )

    def handle_capture_failed(self, message: str) -> None:
        self.capture_failed_flag = True
        self.status_label.setText(self._lm.tr("page.packets.status_live_failed"))
        QMessageBox.critical(
            self,
            self._lm.tr("page.packets.dialog.live_capture_failed_title"),
            self._lm.tr("page.packets.dialog.npcap_hint", message=message),
        )

    def handle_capture_stopped(self) -> None:
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)
        self.import_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.import_decrypted_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)
        if not self.capture_failed_flag:
            self.status_label.setText(
                self._lm.tr("page.packets.status_live_stopped", packets=self.loaded_count, alerts=self.saved_alert_count, skipped=self.capture_skipped_count)
            )

    def clear_packets(self) -> None:
        self.packet_table.clear_packets()
        self._update_filter_status()
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.capture_skipped_count = 0
        self.capture_rate = 0.0
        self.status_label.setText(self._lm.tr("page.packets.status_cleared"))

    def _set_busy(self, busy: bool) -> None:
        self.import_button.setEnabled(not busy)
        self.demo_button.setEnabled(not busy)
        self.import_decrypted_button.setEnabled(not busy)
        self.clear_button.setEnabled(not busy)
        self.start_capture_button.setEnabled(not busy)
        self.refresh_interfaces_button.setEnabled(not busy)

    def update_capture_filter_mode(self, mode: str) -> None:
        if self._filter_mode == "Custom":
            self.custom_filter_text = self.capture_filter_input.text()
        self._filter_mode = mode
        self.filter_timer.stop()
        preset = self.CAPTURE_FILTER_PRESETS.get(mode, "")
        self.capture_filter_input.setReadOnly(mode != "Custom")
        self.capture_filter_input.setText(self.custom_filter_text if mode == "Custom" else preset)
        self.capture_filter_input.setPlaceholderText(
            "tcp.port == 443 or ip.addr == 192.168.1.10" if mode == "Custom" else "All traffic"
        )
        self.apply_packet_filter()

    def schedule_packet_filter(self, _: str = "") -> None:
        if self.capture_filter_combo.currentText() == "Custom":
            self.filter_timer.start()

    def apply_packet_filter(self) -> bool:
        expression = self.capture_filter_input.text().strip()
        try:
            compiled = PacketFilter.compile(expression)
        except PacketFilterError as exc:
            self.filter_error_message = str(exc)
            self.filter_result_label.setText(f"Invalid filter: {self.filter_error_message}")
            self.capture_filter_input.setToolTip(str(exc))
            return False

        self.filter_error_message = ""
        self.packet_filter = compiled
        self.packet_table.set_packet_filter(compiled.matches if compiled.expression else None)
        capture_bpf = compiled.capture_filter or "all traffic"
        self.capture_filter_input.setToolTip(
            "Accepts common Wireshark display filters and BPF syntax. "
            f"Capture BPF: {capture_bpf}"
        )
        self._update_filter_status()
        return True

    def update_visible_row_limit(self, value: int) -> None:
        self.packet_table.set_max_visible_rows(value)
        self._update_filter_status()

    def _update_filter_status(self) -> None:
        if self.filter_error_message:
            self.filter_result_label.setText(f"Invalid filter: {self.filter_error_message}")
            return
        visible = self.packet_table.rowCount()
        buffered = self.packet_table.buffered_packet_count()
        text = f"Showing {visible:,} of {buffered:,} packets"
        capture_filter_changed = self.packet_filter.capture_filter != self.active_capture_filter
        if self.live_worker and self.live_worker.isRunning() and capture_filter_changed:
            text += " (capture filter applies after restart)"
        self.filter_result_label.setText(text)

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

    def shutdown(self, timeout_ms: int = 12_000) -> bool:
        workers: list[QThread] = []
        if self.import_worker and self.import_worker.isRunning():
            self.import_worker.requestInterruption()
            workers.append(self.import_worker)
        if self.live_worker and self.live_worker.isRunning():
            self.live_worker.stop_capture()
            workers.append(self.live_worker)

        return all(worker.wait(timeout_ms) for worker in workers)
