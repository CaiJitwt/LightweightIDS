from __future__ import annotations

from PySide6.QtCore import QTimer, Signal
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
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from detection.analysis.attack_chain import AttackChainAnalyzer
from models import AlertRecord, PacketRecord
from report.report_generator import ReportGenerator
from protection import BlocklistService
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository
from ui.i18n import locale_manager
from ui.styles import configure_responsive_table
from ui.widgets.alert_table import AlertTable
from ui.widgets.evidence_packet_table import EvidencePacketTable


class AlertPage(QWidget):
    RESULT_LIMIT = 2_000
    investigation_requested = Signal(object)

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.alert_repository = AlertRepository(database)
        self.packet_repository = PacketRepository(database)
        self.report_generator = ReportGenerator()
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.blocklist_service = BlocklistService(database)
        self.current_alerts: list[AlertRecord] = []
        self._lm = locale_manager()
        self._retranslating = False
        self._rule_ids = [
            "PORT_SCAN", "SYN_FLOOD", "ICMP_FLOOD", "SENSITIVE_PORT",
            "BLACKLIST_IP", "BRUTE_FORCE", "DNS_ANOMALY", "HTTP_SUSPICIOUS",
            "SQL_INJECTION", "XSS", "MALICIOUS_COMMAND", "ABNORMAL_OUTBOUND",
            "LATERAL_MOVEMENT", "HOST_SCAN", "TLS_FINGERPRINT", "ML_ANOMALY",
            "WEB_ATTACK", "ML_FLOW_ANOMALY", "SIGNATURE_MATCH",
            "BASELINE_DEVIATION", "BANDWIDTH_SPIKE", "SESSION_DURATION_ANOMALY",
        ]
        self.rule_display_names = {
            rid: self._lm.tr(f"rule.{rid}.name") for rid in self._rule_ids
        }

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        toolbar = QHBoxLayout()

        self.severity_filter = QComboBox()
        self.severity_filter.addItems([
            self._lm.tr("severity.all"),
            self._lm.tr("severity.LOW"),
            self._lm.tr("severity.MEDIUM"),
            self._lm.tr("severity.HIGH"),
            self._lm.tr("severity.CRITICAL"),
        ])
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText(self._lm.tr("page.alerts.search_placeholder"))
        self.refresh_button = QPushButton(self._lm.tr("page.alerts.refresh"))
        self.detail_button = QPushButton(self._lm.tr("page.alerts.details"))
        self.confirm_button = QPushButton(self._lm.tr("page.alerts.confirm"))
        self.ignore_button = QPushButton(self._lm.tr("page.alerts.ignore"))
        self.delete_button = QPushButton(self._lm.tr("page.alerts.delete"))
        self.investigate_button = QPushButton(self._lm.tr("page.alerts.investigate"))
        self.export_button = QPushButton(self._lm.tr("page.alerts.export_csv"))
        self.result_label = QLabel()
        self.result_label.setObjectName("PageHint")

        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.keyword_input, 1)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.detail_button)
        toolbar.addWidget(self.confirm_button)
        toolbar.addWidget(self.ignore_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.investigate_button)
        toolbar.addWidget(self.export_button)

        self.table = AlertTable()
        self.detail_title = QLabel(self._lm.tr("page.alerts.detail_section"))
        self.detail_title.setObjectName("SectionTitle")
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setPlaceholderText(self._lm.tr("page.alerts.detail_placeholder"))
        self.detail_view.setMinimumHeight(130)
        self.related_title = QLabel(self._lm.tr("page.alerts.related_packets", count=0))
        self.related_title.setObjectName("SectionTitle")
        self.related_packets_table = EvidencePacketTable()
        self.related_packets_table.setMinimumHeight(150)
        self.chain_title = QLabel(self._lm.tr("page.alerts.attack_chain"))
        self.chain_title.setObjectName("SectionTitle")
        self.chain_table = QTableWidget(0, 4)
        self.chain_table.setHorizontalHeaderLabels([
            self._lm.tr("table.source_ip"),
            self._lm.tr("table.risk"),
            self._lm.tr("table.stages"),
            self._lm.tr("table.alerts"),
        ])
        configure_responsive_table(self.chain_table, stretch_columns=(2,), resize_to_contents_columns=(1, 3))
        self.chain_table.setMinimumHeight(100)

        layout.addLayout(toolbar, 0)
        layout.addWidget(self.result_label)
        layout.addWidget(self.table, 3)
        layout.addWidget(self.detail_title)
        layout.addWidget(self.detail_view, 2)
        layout.addWidget(self.related_title)
        layout.addWidget(self.related_packets_table, 2)
        layout.addWidget(self.chain_title)
        layout.addWidget(self.chain_table, 1)

        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(250)
        self.search_timer.timeout.connect(self.refresh)
        self.severity_filter.currentTextChanged.connect(self.refresh)
        self.keyword_input.textChanged.connect(lambda _text: self.search_timer.start())
        self.refresh_button.clicked.connect(self.refresh)
        self.detail_button.clicked.connect(self.show_selected_detail)
        self.confirm_button.clicked.connect(lambda: self.update_selected_status("confirmed"))
        self.ignore_button.clicked.connect(lambda: self.update_selected_status("ignored"))
        self.delete_button.clicked.connect(self.delete_selected_alert)
        self.investigate_button.clicked.connect(self.add_selected_to_investigation)
        self.export_button.clicked.connect(self.export_csv)
        self.table.itemSelectionChanged.connect(self.render_selected_alert_detail)
        self.related_packets_table.block_requested.connect(self.add_blocklist_entry)
        self.related_packets_table.packet_activated.connect(self.show_packet_detail)

        self._lm.locale_changed.connect(self.retranslate_ui)
        self.refresh()

    # ------------------------------------------------------------------
    # i18n
    # ------------------------------------------------------------------

    def retranslate_ui(self) -> None:
        self._retranslating = True
        self._rebuild_rule_display_names()

        # ── toolbar buttons ───────────────────────────────────────
        self.refresh_button.setText(self._lm.tr("page.alerts.refresh"))
        self.detail_button.setText(self._lm.tr("page.alerts.details"))
        self.confirm_button.setText(self._lm.tr("page.alerts.confirm"))
        self.ignore_button.setText(self._lm.tr("page.alerts.ignore"))
        self.delete_button.setText(self._lm.tr("page.alerts.delete"))
        self.investigate_button.setText(self._lm.tr("page.alerts.investigate"))
        self.export_button.setText(self._lm.tr("page.alerts.export_csv"))

        # ── severity combo ────────────────────────────────────────
        self.severity_filter.blockSignals(True)
        saved_severity = self.severity_filter.currentText()
        self.severity_filter.clear()
        self.severity_filter.addItems([
            self._lm.tr("severity.all"),
            self._lm.tr("severity.LOW"),
            self._lm.tr("severity.MEDIUM"),
            self._lm.tr("severity.HIGH"),
            self._lm.tr("severity.CRITICAL"),
        ])
        # Restore selection if the saved text matches one of the new items
        idx = self.severity_filter.findText(saved_severity)
        if idx >= 0:
            self.severity_filter.setCurrentIndex(idx)
        else:
            self.severity_filter.setCurrentIndex(0)
        self.severity_filter.blockSignals(False)

        # ── search placeholder ────────────────────────────────────
        self.keyword_input.setPlaceholderText(self._lm.tr("page.alerts.search_placeholder"))

        # ── section titles ────────────────────────────────────────
        self.detail_title.setText(self._lm.tr("page.alerts.detail_section"))
        self.chain_title.setText(self._lm.tr("page.alerts.attack_chain"))

        # ── detail placeholder ────────────────────────────────────
        self.detail_view.setPlaceholderText(self._lm.tr("page.alerts.detail_placeholder"))

        # ── chain table headers ───────────────────────────────────
        self.chain_table.setHorizontalHeaderLabels([
            self._lm.tr("table.source_ip"),
            self._lm.tr("table.risk"),
            self._lm.tr("table.stages"),
            self._lm.tr("table.alerts"),
        ])

        # ── alert table headers ───────────────────────────────────
        self.table.retranslate_ui()

        self._retranslating = False

        # Refresh to update dynamic content (result label, related packets label, detail text, chain data)
        self.refresh()

    def _rebuild_rule_display_names(self) -> None:
        self.rule_display_names = {
            rid: self._lm.tr(f"rule.{rid}.name") for rid in self._rule_ids
        }

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def add_selected_to_investigation(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            QMessageBox.information(self, self._lm.tr("page.alerts.no_alert_selected"), self._lm.tr("page.alerts.please_select"))
            return
        self.investigation_requested.emit(alert)

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        if self._retranslating:
            return
        selected_alert_id = self.table.selected_alert_id()
        severity_text = self.severity_filter.currentText()
        severity = None if severity_text == self._lm.tr("severity.all") else severity_text
        keyword = self.keyword_input.text().strip()
        self.current_alerts = self.alert_repository.list_all(
            severity=severity,
            keyword=keyword,
            limit=self.RESULT_LIMIT,
        )
        self.current_alerts = [self._display_alert(alert) for alert in self.current_alerts]
        self.table.set_alerts(self.current_alerts)
        if selected_alert_id is not None:
            self.table.select_alert_id(selected_alert_id)
        self.result_label.setText(
            self._lm.tr("page.alerts.result_label", count=len(self.current_alerts), limit=self.RESULT_LIMIT)
        )
        self.render_selected_alert_detail()
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
            QMessageBox.information(self, self._lm.tr("page.alerts.no_alert_selected"), self._lm.tr("page.alerts.please_select"))
            return

        QMessageBox.information(self, self._lm.tr("page.alerts.alert_details_title"), self._alert_detail_text(alert))

    def render_selected_alert_detail(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            self.detail_view.clear()
            self.related_title.setText(self._lm.tr("page.alerts.related_packets", count=0))
            self.related_packets_table.set_packets([])
            return
        packets = self.packet_repository.list_related_to_alert(alert)
        self.detail_view.setPlainText(self._alert_detail_text(alert, packets))
        self.related_title.setText(self._lm.tr("page.alerts.related_packets", count=len(packets)))
        self.related_packets_table.set_packets(packets)

    def _alert_detail_text(self, alert: AlertRecord, packets: list[PacketRecord] | None = None) -> str:
        packets = packets if packets is not None else self.packet_repository.list_related_to_alert(alert)
        packet = packets[-1] if packets else None
        packet_detail = (
            self._packet_detail_text(packet)
            if packet
            else self._lm.tr("page.alerts.matching_packet_not_found")
        )
        return self._lm.tr(
            "page.alerts.alert_detail_template",
            timestamp=str(alert.timestamp),
            severity=alert.severity or "",
            alert_type=alert.alert_type or "",
            rule_name=alert.rule_name or "",
            rule_id=alert.rule_id or "",
            src=f"{alert.src_ip or ''}:{alert.src_port or ''}",
            dst=f"{alert.dst_ip or ''}:{alert.dst_port or ''}",
            protocol=alert.protocol or "",
            status=alert.status or "",
            description=alert.description or "",
            evidence=alert.evidence or "",
            packet_count=str(len(packets)),
            packet_detail=packet_detail,
        )

    def add_blocklist_entry(self, field: str, value: str, protocol: str) -> None:
        kind = "IP" if field.endswith("IP") else "PORT"
        answer = QMessageBox.question(
            self,
            self._lm.tr("page.alerts.enforce_block_title"),
            self._lm.tr("page.alerts.enforce_block_msg", field=field, value=value),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            entry, result = self.blocklist_service.add_and_enforce(
                kind=kind,
                value=value,
                field=field,
                protocol=protocol,
            )
        except ValueError as exc:
            QMessageBox.warning(self, self._lm.tr("page.alerts.invalid_block_value"), str(exc))
            return
        message = f"Blocklist entry #{entry.id}: {result.status}."
        if result.message:
            message += f"\n\n{result.message}"
        if result.success:
            QMessageBox.information(self, self._lm.tr("blocklist.block_active"), message)
        else:
            QMessageBox.warning(self, self._lm.tr("blocklist.block_not_enforced"), message)

    def show_packet_detail(self, packet: object) -> None:
        if isinstance(packet, PacketRecord):
            QMessageBox.information(self, self._lm.tr("page.alerts.packet_details_title"), self._packet_detail_text(packet))

    def _packet_detail_text(self, packet: PacketRecord) -> str:
        return self._lm.tr(
            "page.alerts.packet_detail_template",
            packet_id=str(packet.id or ""),
            timestamp=str(packet.timestamp),
            src=f"{packet.src_ip or ''}:{packet.src_port or ''}",
            dst=f"{packet.dst_ip or ''}:{packet.dst_port or ''}",
            protocol=str(packet.protocol),
            length=str(packet.length),
            tcp_flags=str(packet.tcp_flags or ""),
            dns_query=str(packet.dns_query or ""),
            http_method=str(packet.http_method or ""),
            http_host=str(packet.http_host or ""),
            http_path=str(packet.http_path or ""),
            raw_summary=str(packet.raw_summary),
        )

    def _matching_packet(self, alert: AlertRecord) -> PacketRecord | None:
        try:
            packets = self.packet_repository.list_related_to_alert(alert)
            return packets[-1] if packets else None
        except Exception:
            return None

    def update_selected_status(self, status: str) -> None:
        alert_id = self.table.selected_alert_id()
        if alert_id is None:
            QMessageBox.information(self, self._lm.tr("page.alerts.no_alert_selected"), self._lm.tr("page.alerts.please_select"))
            return

        if not self.alert_repository.update_status(alert_id, status):
            QMessageBox.warning(self, self._lm.tr("page.alerts.update_failed"), self._lm.tr("page.alerts.update_failed_msg"))
            return
        self.refresh()

    def delete_selected_alert(self) -> None:
        alert = self._selected_alert()
        if alert is None or alert.id is None:
            QMessageBox.information(self, self._lm.tr("page.alerts.no_alert_selected"), self._lm.tr("page.alerts.please_select"))
            return

        answer = QMessageBox.question(
            self,
            self._lm.tr("page.alerts.delete_title"),
            self._lm.tr("page.alerts.delete_msg"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        if not self.alert_repository.delete(alert.id):
            QMessageBox.warning(self, self._lm.tr("page.alerts.delete_failed"), self._lm.tr("page.alerts.delete_failed_msg"))
            return
        self.refresh()

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._lm.tr("page.alerts.export_dialog"),
            "alerts.csv",
            "CSV files (*.csv);;All files (*)",
        )
        if not path:
            return

        self.report_generator.export_alerts_csv(self.current_alerts, path)
        QMessageBox.information(self, self._lm.tr("page.alerts.export_complete"), self._lm.tr("page.alerts.export_csv_done", path=path))

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
        desc_key = f"alert.desc.{alert.alert_type}"
        translated = self._lm.tr(desc_key)
        if translated != desc_key:
            return translated
        return self._lm.tr("alert.desc.default")

    def _contains_non_ascii(self, value: str) -> bool:
        return any(ord(char) > 127 for char in value)
