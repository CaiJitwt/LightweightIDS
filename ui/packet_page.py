from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from capture.interface_manager import InterfaceManager
from capture.live_capture import LiveCapture
from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from models import AlertRecord, CustomRuleRecord, PacketRecord, RuleRecord
from parser.packet_parser import PacketParser
from storage.database import Database
from storage.repositories import AlertRepository, CustomRuleRepository, PacketRepository, RuleRepository
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


class LiveCaptureWorker(QThread):
    packet_processed = Signal(list, list)
    capture_failed = Signal(str)
    capture_stopped = Signal()

    def __init__(
        self,
        interface: str | None,
        rule_records: list[RuleRecord],
        custom_rule_records: list[CustomRuleRecord],
    ) -> None:
        super().__init__()
        self.interface = interface
        self.rule_records = rule_records
        self.custom_rule_records = custom_rule_records
        self.parser = PacketParser()
        self.capture: LiveCapture | None = None

    def run(self) -> None:
        engine = DetectionEngine.from_rule_records(self.rule_records, self.custom_rule_records, alert_cooldown_seconds=10)

        def handle_raw_packet(raw_packet: object) -> None:
            packet = self.parser.parse(raw_packet)
            alerts = engine.process_packet(packet)
            self.packet_processed.emit([packet], alerts)

        self.capture = LiveCapture(interface=self.interface, packet_callback=handle_raw_packet)
        try:
            self.capture.start()
        except Exception as exc:
            self.capture_failed.emit(str(exc))
        finally:
            self.capture_stopped.emit()

    def stop_capture(self) -> None:
        if self.capture:
            self.capture.stop()


class PacketPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.rule_repository = RuleRepository(database)
        self.custom_rule_repository = CustomRuleRepository(database)
        self.interface_manager = InterfaceManager()
        self.import_worker: PcapImportWorker | None = None
        self.live_worker: LiveCaptureWorker | None = None
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0

        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(220)
        self.refresh_interfaces_button = QPushButton("刷新网卡")
        self.import_button = QPushButton("导入 pcap")
        self.start_capture_button = QPushButton("开始抓包")
        self.stop_capture_button = QPushButton("停止抓包")
        self.clear_button = QPushButton("清空")
        self.stop_capture_button.setEnabled(False)

        toolbar.addWidget(self.interface_combo)
        toolbar.addWidget(self.refresh_interfaces_button)
        toolbar.addWidget(self.import_button)
        toolbar.addWidget(self.start_capture_button)
        toolbar.addWidget(self.stop_capture_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addStretch()

        self.status_label = QLabel("请选择本地 pcap 文件进行离线分析，或选择网卡开始实时抓包。")
        self.status_label.setObjectName("PageHint")
        self.packet_table = PacketTable()

        layout.addLayout(toolbar)
        layout.addWidget(self.status_label)
        layout.addWidget(self.packet_table)

        self.import_button.clicked.connect(self.select_pcap_file)
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.start_capture_button.clicked.connect(self.start_live_capture)
        self.stop_capture_button.clicked.connect(self.stop_live_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.refresh_interfaces()

    def refresh_interfaces(self) -> None:
        self.interface_combo.clear()
        self.interface_combo.addItem("默认网卡", None)
        try:
            for interface in self.interface_manager.list_interfaces():
                self.interface_combo.addItem(interface, interface)
            self.status_label.setText("网卡列表已刷新。Windows 实时抓包可能需要 Npcap 和管理员权限。")
        except Exception as exc:
            self.status_label.setText(f"获取网卡列表失败：{exc}")

    def select_pcap_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 pcap 文件",
            "",
            "pcap 文件 (*.pcap *.pcapng *.cap);;所有文件 (*)",
        )
        if path:
            self.start_import(path)

    def start_import(self, path: str | Path) -> None:
        if self.import_worker and self.import_worker.isRunning():
            QMessageBox.information(self, "正在导入", "当前已有 pcap 文件正在导入，请稍后。")
            return

        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.packet_table.clear_packets()
        self._set_busy(True)
        self.status_label.setText(f"正在导入并检测：{Path(path).name}")

        self.import_worker = PcapImportWorker(
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
        self.status_label.setText("实时抓包已启动，检测结果会持续写入数据库。")
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)
        self.import_button.setEnabled(False)
        self.refresh_interfaces_button.setEnabled(False)

        self.live_worker = LiveCaptureWorker(
            interface=interface,
            rule_records=self.rule_repository.list_all(),
            custom_rule_records=self.custom_rule_repository.list_all(),
        )
        self.live_worker.packet_processed.connect(self.handle_processed_batch)
        self.live_worker.capture_failed.connect(self.handle_capture_failed)
        self.live_worker.capture_stopped.connect(self.handle_capture_stopped)
        self.live_worker.start()

    def stop_live_capture(self) -> None:
        if self.live_worker and self.live_worker.isRunning():
            self.status_label.setText("正在停止实时抓包...")
            self.live_worker.stop_capture()

    def handle_processed_batch(self, packets: list[PacketRecord], alerts: list[AlertRecord]) -> None:
        self.loaded_count += len(packets)
        self.packet_table.add_packets(packets)
        self.saved_packet_count += self.packet_repository.add_many(packets)
        self.saved_alert_count += self.alert_repository.add_many(alerts)
        self.status_label.setText(
            f"已处理 {self.loaded_count} 个数据包，已保存 {self.saved_packet_count} 条流量记录，"
            f"生成 {self.saved_alert_count} 条告警。"
        )

    def handle_import_failed(self, message: str) -> None:
        self._set_busy(False)
        self.status_label.setText("pcap 导入失败。")
        QMessageBox.critical(self, "导入失败", message)

    def handle_import_finished(self, packet_total: int, alert_total: int) -> None:
        self._set_busy(False)
        self.status_label.setText(f"导入完成：共解析 {packet_total} 个数据包，生成 {alert_total} 条告警。")

    def handle_capture_failed(self, message: str) -> None:
        self.status_label.setText("实时抓包失败。")
        QMessageBox.critical(self, "实时抓包失败", f"{message}\n\nWindows 下请确认已安装 Npcap，并尝试以管理员权限运行。")

    def handle_capture_stopped(self) -> None:
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)
        self.import_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)
        if "失败" not in self.status_label.text():
            self.status_label.setText("实时抓包已停止。")

    def clear_packets(self) -> None:
        self.packet_table.clear_packets()
        self.loaded_count = 0
        self.saved_packet_count = 0
        self.saved_alert_count = 0
        self.status_label.setText("表格已清空，可继续导入 pcap 文件或实时抓包。")

    def _set_busy(self, busy: bool) -> None:
        self.import_button.setEnabled(not busy)
        self.clear_button.setEnabled(not busy)
        self.start_capture_button.setEnabled(not busy)
        self.refresh_interfaces_button.setEnabled(not busy)
