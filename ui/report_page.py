from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from report.report_generator import ReportGenerator
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository
from ui.i18n import locale_manager


class ReportPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self._lm = locale_manager()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.report_generator = ReportGenerator()

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        self.hint = QLabel(self._lm.tr("page.reports.hint"))
        self.hint.setObjectName("PageHint")
        self.hint.setWordWrap(True)
        self.html_button = QPushButton(self._lm.tr("page.reports.export_html"))
        self.csv_button = QPushButton(self._lm.tr("page.reports.export_csv"))
        self.json_button = QPushButton(self._lm.tr("page.reports.export_json"))

        for button in [self.html_button, self.csv_button, self.json_button]:
            button.setMinimumHeight(34)

        layout.addWidget(self.hint)
        layout.addWidget(self.html_button)
        layout.addWidget(self.csv_button)
        layout.addWidget(self.json_button)
        layout.addStretch()

        self.html_button.clicked.connect(self.export_html)
        self.csv_button.clicked.connect(self.export_csv)
        self.json_button.clicked.connect(self.export_json)

        self._lm.locale_changed.connect(self.retranslate_ui)

    def retranslate_ui(self) -> None:
        """Update all user-visible text after a locale change."""
        self.hint.setText(self._lm.tr("page.reports.hint"))
        self.html_button.setText(self._lm.tr("page.reports.export_html"))
        self.csv_button.setText(self._lm.tr("page.reports.export_csv"))
        self.json_button.setText(self._lm.tr("page.reports.export_json"))

    def export_html(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._lm.tr("page.reports.dialog.html"),
            "lightweight_ids_report.html",
            "HTML files (*.html);;All files (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        packets = self.packet_repository.list_recent()
        statistics = self._build_statistics()
        self.report_generator.generate_html_report(alerts, packets, statistics, path)
        QMessageBox.information(
            self,
            self._lm.tr("page.reports.export_complete"),
            self._lm.tr("page.reports.html_done", path=path),
        )

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._lm.tr("page.reports.dialog.csv"),
            "alerts.csv",
            "CSV files (*.csv);;All files (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        self.report_generator.export_alerts_csv(alerts, path)
        QMessageBox.information(
            self,
            self._lm.tr("page.reports.export_complete"),
            self._lm.tr("page.reports.csv_done", path=path),
        )

    def export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._lm.tr("page.reports.dialog.json"),
            "alerts.json",
            "JSON files (*.json);;All files (*)",
        )
        if not path:
            return

        alerts = self.alert_repository.list_all()
        self.report_generator.export_alerts_json(alerts, path)
        QMessageBox.information(
            self,
            self._lm.tr("page.reports.export_complete"),
            self._lm.tr("page.reports.json_done", path=path),
        )

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
