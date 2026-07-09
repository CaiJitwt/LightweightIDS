from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from detection.analysis.attack_chain import AttackChainAnalyzer
from models import AlertRecord
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
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.current_alerts: list[AlertRecord] = []
        self.rule_display_names = {
            "PORT_SCAN": "Port scan detection",
            "SYN_FLOOD": "SYN flood detection",
            "ICMP_FLOOD": "ICMP flood detection",
            "SENSITIVE_PORT": "Sensitive port access",
            "BLACKLIST_IP": "Blacklisted IP match",
            "BRUTE_FORCE": "Brute-force connection detection",
            "DNS_ANOMALY": "DNS anomaly detection",
            "HTTP_SUSPICIOUS": "Suspicious HTTP request",
            "SQL_INJECTION": "SQL injection detection",
            "XSS": "XSS detection",
            "MALICIOUS_COMMAND": "Malicious command detection",
            "ABNORMAL_OUTBOUND": "Abnormal outbound traffic",
            "LATERAL_MOVEMENT": "Lateral movement",
            "HOST_SCAN": "Host scan",
            "TLS_FINGERPRINT": "TLS fingerprint risk",
            "ML_ANOMALY": "ML anomaly score",
            "WEB_ATTACK": "Web attack (advanced)",
        }

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        toolbar = QHBoxLayout()

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All severities", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Search rule, IP, description or evidence")
        self.refresh_button = QPushButton("Refresh")
        self.detail_button = QPushButton("Details")
        self.confirm_button = QPushButton("Confirm")
        self.ignore_button = QPushButton("Ignore")
        self.delete_button = QPushButton("Delete")
        self.export_button = QPushButton("Export CSV")

        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.keyword_input, 1)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.detail_button)
        toolbar.addWidget(self.confirm_button)
        toolbar.addWidget(self.ignore_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.export_button)

        self.table = AlertTable()
        self.chain_title = QLabel("Attack chain view")
        self.chain_title.setStyleSheet("font-weight: 700; color: #1f2933;")
        self.chain_table = QTableWidget(0, 4)
        self.chain_table.setHorizontalHeaderLabels(["Source IP", "Risk", "Stages", "Alerts"])
        self.chain_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.chain_table.horizontalHeader().setStretchLastSection(True)
        self.chain_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.chain_table.setAlternatingRowColors(True)
        self.chain_table.setMinimumHeight(130)

        layout.addLayout(toolbar)
        layout.addWidget(self.table, 3)
        layout.addWidget(self.chain_title)
        layout.addWidget(self.chain_table, 1)

        self.severity_filter.currentTextChanged.connect(self.refresh)
        self.keyword_input.textChanged.connect(self.refresh)
        self.refresh_button.clicked.connect(self.refresh)
        self.detail_button.clicked.connect(self.show_selected_detail)
        self.confirm_button.clicked.connect(lambda: self.update_selected_status("confirmed"))
        self.ignore_button.clicked.connect(lambda: self.update_selected_status("ignored"))
        self.delete_button.clicked.connect(self.delete_selected_alert)
        self.export_button.clicked.connect(self.export_csv)

        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        severity_text = self.severity_filter.currentText()
        severity = None if severity_text == "All severities" else severity_text
        keyword = self.keyword_input.text().strip()
        self.current_alerts = self.alert_repository.list_all(severity=severity, keyword=keyword)
        self.current_alerts = [self._display_alert(alert) for alert in self.current_alerts]
        self.table.set_alerts(self.current_alerts)
        self._render_attack_chains()

    def _render_attack_chains(self) -> None:
        chains = self.attack_chain_analyzer.analyze(self.current_alerts)
        self.chain_table.setRowCount(len(chains))
        for row, chain in enumerate(chains):
            values = [chain.source_ip, str(chain.risk_score), chain.summary, str(len(chain.alerts))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.chain_table.setItem(row, column, item)
        self.chain_table.setColumnWidth(0, 140)
        self.chain_table.setColumnWidth(1, 70)
        self.chain_table.setColumnWidth(3, 70)
        self.chain_table.resizeRowsToContents()

    def show_selected_detail(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            QMessageBox.information(self, "No alert selected", "Please select an alert first.")
            return

        detail = (
            f"Time: {alert.timestamp}\n"
            f"Severity: {alert.severity}\n"
            f"Type: {alert.alert_type}\n"
            f"Rule: {alert.rule_name} ({alert.rule_id})\n"
            f"Source: {alert.src_ip or ''}:{alert.src_port or ''}\n"
            f"Destination: {alert.dst_ip or ''}:{alert.dst_port or ''}\n"
            f"Protocol: {alert.protocol or ''}\n"
            f"Status: {alert.status}\n\n"
            f"Description: {alert.description}\n\n"
            f"Evidence: {alert.evidence}"
        )
        QMessageBox.information(self, "Alert details", detail)

    def update_selected_status(self, status: str) -> None:
        alert_id = self.table.selected_alert_id()
        if alert_id is None:
            QMessageBox.information(self, "No alert selected", "Please select an alert first.")
            return

        if not self.alert_repository.update_status(alert_id, status):
            QMessageBox.warning(self, "Update failed", "The selected alert could not be updated. Please refresh and try again.")
            return
        self.refresh()

    def delete_selected_alert(self) -> None:
        alert = self._selected_alert()
        if alert is None or alert.id is None:
            QMessageBox.information(self, "No alert selected", "Please select an alert first.")
            return

        answer = QMessageBox.question(
            self,
            "Delete alert",
            "Delete the selected alert? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        if not self.alert_repository.delete(alert.id):
            QMessageBox.warning(self, "Delete failed", "The selected alert could not be deleted. Please refresh and try again.")
            return
        self.refresh()

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export alerts CSV",
            "alerts.csv",
            "CSV files (*.csv);;All files (*)",
        )
        if not path:
            return

        self.report_generator.export_alerts_csv(self.current_alerts, path)
        QMessageBox.information(self, "Export complete", f"Alerts CSV exported to: {path}")

    def _selected_alert(self) -> AlertRecord | None:
        alert_id = self.table.selected_alert_id()
        if alert_id is None:
            return None
        for alert in self.current_alerts:
            if alert.id == alert_id:
                return alert
        return None

    def _display_alert(self, alert: AlertRecord) -> AlertRecord:
        rule_name = self.rule_display_names.get(alert.rule_id, alert.rule_name)
        description = alert.description
        if self._contains_non_ascii(description):
            description = self._fallback_description(alert)
        return AlertRecord(
            id=alert.id,
            timestamp=alert.timestamp,
            rule_id=alert.rule_id,
            rule_name=rule_name,
            alert_type=alert.alert_type,
            severity=alert.severity,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            description=description,
            evidence=alert.evidence,
            status=alert.status,
        )

    def _fallback_description(self, alert: AlertRecord) -> str:
        descriptions = {
            "SENSITIVE_PORT_ACCESS": "Detected access to a sensitive service port.",
            "BLACKLIST_IP": "Packet matched a blacklisted IP address.",
            "PORT_SCAN": "Source IP accessed many ports on the same target.",
            "SYN_FLOOD": "Detected many TCP SYN packets in a short time window.",
            "ICMP_FLOOD": "Detected many ICMP packets in a short time window.",
            "BRUTE_FORCE": "Detected many service connection attempts in a short time window.",
            "DNS_QUERY_FREQUENCY": "Detected high-frequency DNS queries.",
            "DNS_TUNNELING_SUSPECTED": "Detected an unusually long DNS query.",
            "DGA_DOMAIN_SUSPECTED": "Detected a random-looking high-entropy domain.",
            "HTTP_SUSPICIOUS": "Detected suspicious HTTP request indicators.",
            "SQL_INJECTION": "Detected suspicious SQL injection indicators.",
            "XSS": "Detected suspicious cross-site scripting indicators.",
            "MALICIOUS_COMMAND": "Detected suspicious command execution indicators.",
            "WEB_ATTACK": "Detected advanced web attack indicators (XXE, SSTI, deserialization, webshell).",
        }
        return descriptions.get(alert.alert_type, "Alert matched the detection rule.")

    def _contains_non_ascii(self, value: str) -> bool:
        return any(ord(char) > 127 for char in value)
