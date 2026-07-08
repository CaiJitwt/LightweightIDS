from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from report.report_generator import ReportGenerator
from storage.database import Database
from storage.repositories import AlertRepository
from ui.widgets.alert_table import AlertTable


class AlertPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.alert_repository = AlertRepository(database)
        self.report_generator = ReportGenerator()
        self.current_alerts = []

        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["全部等级", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("搜索规则、IP、描述或证据")
        self.refresh_button = QPushButton("刷新")
        self.detail_button = QPushButton("查看详情")
        self.confirm_button = QPushButton("确认")
        self.ignore_button = QPushButton("忽略")
        self.export_button = QPushButton("导出 CSV")

        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.keyword_input)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.detail_button)
        toolbar.addWidget(self.confirm_button)
        toolbar.addWidget(self.ignore_button)
        toolbar.addWidget(self.export_button)
        toolbar.addStretch()

        self.table = AlertTable()
        layout.addLayout(toolbar)
        layout.addWidget(self.table)

        self.severity_filter.currentTextChanged.connect(self.refresh)
        self.keyword_input.textChanged.connect(self.refresh)
        self.refresh_button.clicked.connect(self.refresh)
        self.detail_button.clicked.connect(self.show_selected_detail)
        self.confirm_button.clicked.connect(lambda: self.update_selected_status("confirmed"))
        self.ignore_button.clicked.connect(lambda: self.update_selected_status("ignored"))
        self.export_button.clicked.connect(self.export_csv)

        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        severity = self.severity_filter.currentText()
        keyword = self.keyword_input.text().strip()
        self.current_alerts = self.alert_repository.list_all(severity=severity, keyword=keyword)
        self.table.set_alerts(self.current_alerts)

    def show_selected_detail(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            QMessageBox.information(self, "未选择告警", "请先选择一条告警。")
            return

        detail = (
            f"时间：{alert.timestamp}\n"
            f"等级：{alert.severity}\n"
            f"类型：{alert.alert_type}\n"
            f"规则：{alert.rule_name} ({alert.rule_id})\n"
            f"源：{alert.src_ip or ''}:{alert.src_port or ''}\n"
            f"目标：{alert.dst_ip or ''}:{alert.dst_port or ''}\n"
            f"协议：{alert.protocol or ''}\n"
            f"状态：{alert.status}\n\n"
            f"描述：{alert.description}\n\n"
            f"证据：{alert.evidence}"
        )
        QMessageBox.information(self, "告警详情", detail)

    def update_selected_status(self, status: str) -> None:
        alert_id = self.table.selected_alert_id()
        if alert_id is None:
            QMessageBox.information(self, "未选择告警", "请先选择一条告警。")
            return

        self.alert_repository.update_status(alert_id, status)
        self.refresh()

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出告警 CSV",
            "alerts.csv",
            "CSV 文件 (*.csv);;所有文件 (*)",
        )
        if not path:
            return

        self.report_generator.export_alerts_csv(self.current_alerts, path)
        QMessageBox.information(self, "导出完成", f"告警 CSV 已导出：{path}")

    def _selected_alert(self):
        alert_id = self.table.selected_alert_id()
        if alert_id is None:
            return None
        for alert in self.current_alerts:
            if alert.id == alert_id:
                return alert
        return None
