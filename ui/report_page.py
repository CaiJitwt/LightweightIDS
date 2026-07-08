from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from report.report_generator import ReportGenerator
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository


class ReportPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.report_generator = ReportGenerator()

        layout = QVBoxLayout(self)
        self.hint = QLabel("可导出 HTML 检测报告，也可单独导出告警 CSV 或 JSON。")
        self.hint.setObjectName("PageHint")
        self.html_button = QPushButton("导出 HTML 报告")
        self.csv_button = QPushButton("导出告警 CSV")
        self.json_button = QPushButton("导出告警 JSON")

        layout.addWidget(self.hint)
        layout.addWidget(self.html_button)
        layout.addWidget(self.csv_button)
        layout.addWidget(self.json_button)
        layout.addStretch()

        self.html_button.clicked.connect(self.export_html)
        self.csv_button.clicked.connect(self.export_csv)
        self.json_button.clicked.connect(self.export_json)

    def export_html(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出 HTML 报告",
            "lightweight_ids_report.html",
            "HTML 文件 (*.html);;所有文件 (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        packets = self.packet_repository.list_recent()
        statistics = self._build_statistics()
        self.report_generator.generate_html_report(alerts, packets, statistics, path)
        QMessageBox.information(self, "导出完成", f"HTML 报告已导出：{path}")

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出告警 CSV",
            "alerts.csv",
            "CSV 文件 (*.csv);;所有文件 (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        self.report_generator.export_alerts_csv(alerts, path)
        QMessageBox.information(self, "导出完成", f"告警 CSV 已导出：{path}")

    def export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出告警 JSON",
            "alerts.json",
            "JSON 文件 (*.json);;所有文件 (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        self.report_generator.export_alerts_json(alerts, path)
        QMessageBox.information(self, "导出完成", f"告警 JSON 已导出：{path}")

    def _build_statistics(self) -> dict[str, object]:
        severity_distribution = self.alert_repository.count_by_severity()
        return {
            "packet_count": self.packet_repository.count(),
            "alert_count": self.alert_repository.count(),
            "severity_distribution": severity_distribution,
            "alert_type_distribution": self.alert_repository.count_by_type(),
            "protocol_distribution": self.packet_repository.protocol_distribution(),
            "top_src_ips": self.packet_repository.top_src_ips(),
            "top_dst_ports": self.packet_repository.top_dst_ports(),
            "high_or_critical_alerts": severity_distribution.get("HIGH", 0) + severity_distribution.get("CRITICAL", 0),
        }
