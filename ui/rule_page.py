from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.constants import PROJECT_ROOT
from models import CustomRuleRecord, RuleRecord
from protection import BlocklistService
from storage.blocklist_repository import BlocklistEntryRepository
from storage.database import Database
from storage.repositories import AlertRepository, BlacklistRepository, CustomRuleRepository, PacketRepository, RuleRepository
from ui.styles import apply_semantic_style, apply_severity_style, configure_responsive_table


PROTOCOL_OPTIONS = ["Any", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "DNS", "HTTP", "HTTPS", "TLS", "DHCP", "MDNS", "LLMNR", "NBNS", "NTP", "QUIC"]
SEVERITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class RulePage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.alert_repository = AlertRepository(database)
        self.packet_repository = PacketRepository(database)
        self.rule_repository = RuleRepository(database)
        self.custom_rule_repository = CustomRuleRepository(database)
        self.blacklist_repository = BlacklistRepository(PROJECT_ROOT / "config" / "blacklist.txt")
        self.blocklist_entry_repository = BlocklistEntryRepository(database)
        self.blocklist_service = BlocklistService(database)
        self.current_rules: list[RuleRecord] = []
        self.current_custom_rules: list[CustomRuleRecord] = []
        self.source_ip_options: list[str] = ["Any"]
        self.destination_ip_options: list[str] = ["Any"]

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        button_bar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.save_button = QPushButton("Save")
        self.restore_button = QPushButton("Restore defaults")
        self.add_custom_button = QPushButton("Add custom rule")
        self.delete_custom_button = QPushButton("Delete selected rule")
        self.save_blacklist_button = QPushButton("Save blacklist")
        self.add_enforced_block_button = QPushButton("Add enforced block")
        self.remove_enforced_block_button = QPushButton("Remove enforced block")
        self.retry_enforcement_button = QPushButton("Retry enforcement")
        for button in [
            self.refresh_button,
            self.save_button,
            self.restore_button,
            self.add_custom_button,
            self.delete_custom_button,
            self.save_blacklist_button,
        ]:
            button.setMinimumHeight(32)
            button_bar.addWidget(button)
        button_bar.addStretch()

        self.table = QTableWidget(0, 12)
        self.table.setHorizontalHeaderLabels(
            [
                "ID",
                "Name",
                "Category",
                "Severity",
                "Enabled",
                "Threshold",
                "Window (s)",
                "Description",
                "Feedback",
                "Alerts",
                "Confirmed",
                "Ignored",
            ]
        )
        self._configure_table(self.table, stretch_columns=(1, 7, 8), resize_to_contents_columns=(3, 4, 5, 6, 9, 10, 11))

        self.custom_table = QTableWidget(0, 11)
        self.custom_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Severity", "Enabled", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port", "Keyword", "Description"]
        )
        self._configure_table(self.custom_table, stretch_columns=(1, 5, 6, 9, 10), resize_to_contents_columns=(0, 2, 3, 4, 7, 8))

        self.blacklist_editor = QTextEdit()
        self.blacklist_editor.setPlaceholderText("One IP address per line. Empty lines are ignored.")
        self.blacklist_editor.setMaximumHeight(100)
        blocklist_button_bar = QHBoxLayout()
        for button in [
            self.add_enforced_block_button,
            self.remove_enforced_block_button,
            self.retry_enforcement_button,
        ]:
            button.setMinimumHeight(32)
            blocklist_button_bar.addWidget(button)
        blocklist_button_bar.addStretch()
        self.enforced_blocklist_table = QTableWidget(0, 8)
        self.enforced_blocklist_table.setHorizontalHeaderLabels(
            ["ID", "Kind", "Value", "Field", "Protocol", "Status", "Error", "Updated"]
        )
        self._configure_table(
            self.enforced_blocklist_table,
            stretch_columns=(2, 6),
            resize_to_contents_columns=(0, 1, 3, 4, 5, 7),
        )

        builtin_label = QLabel("Built-in detection rules")
        custom_label = QLabel("Custom rules: empty fields mean no restriction. Use drop-downs for protocol and severity.")
        blacklist_label = QLabel("Detection-only IP watchlist")
        enforced_label = QLabel("Enforced IP and port blocklist")
        for label in [builtin_label, custom_label, blacklist_label, enforced_label]:
            label.setObjectName("SectionTitle")

        layout.addLayout(button_bar)
        layout.addWidget(builtin_label)
        layout.addWidget(self.table, 2)
        layout.addWidget(custom_label)
        layout.addWidget(self.custom_table, 3)
        layout.addWidget(blacklist_label)
        layout.addWidget(self.blacklist_editor)
        layout.addWidget(enforced_label)
        layout.addLayout(blocklist_button_bar)
        layout.addWidget(self.enforced_blocklist_table, 1)

        self.refresh_button.clicked.connect(self.refresh)
        self.save_button.clicked.connect(self.save_rules)
        self.restore_button.clicked.connect(self.restore_defaults)
        self.add_custom_button.clicked.connect(self.add_custom_rule_row)
        self.delete_custom_button.clicked.connect(self.delete_selected_custom_rule)
        self.save_blacklist_button.clicked.connect(self.save_blacklist)
        self.add_enforced_block_button.clicked.connect(self.add_enforced_block)
        self.remove_enforced_block_button.clicked.connect(self.remove_enforced_block)
        self.retry_enforcement_button.clicked.connect(self.retry_enforcement)

        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        self.current_rules = self.rule_repository.list_all()
        self.current_custom_rules = self.custom_rule_repository.list_all()
        self._refresh_ip_options()
        self._render_builtin_rules()
        self._render_custom_rules()
        self.blacklist_editor.setPlainText("\n".join(self.blacklist_repository.list_all()))
        self._render_enforced_blocklist()

    def _render_enforced_blocklist(self) -> None:
        entries = self.blocklist_entry_repository.list_all()
        self.enforced_blocklist_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = [
                str(entry.id or ""),
                entry.kind,
                entry.value,
                entry.field,
                entry.protocol,
                entry.enforcement_status,
                entry.enforcement_error,
                entry.updated_at,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, entry.id)
                if column == 5:
                    apply_semantic_style(item, entry.enforcement_status)
                self.enforced_blocklist_table.setItem(row, column, item)

    def _render_builtin_rules(self) -> None:
        feedback_by_rule = self.alert_repository.rule_feedback()
        self.table.setRowCount(len(self.current_rules))
        for row_index, rule in enumerate(self.current_rules):
            for column_index, value in enumerate([rule.id, rule.name, rule.category, rule.severity]):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                item.setToolTip(value)
                if column_index == 3:
                    apply_severity_style(item, value)
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row_index, column_index, item)

            enabled_box = QCheckBox()
            enabled_box.setChecked(rule.enabled)
            self.table.setCellWidget(row_index, 4, enabled_box)

            threshold_box = QSpinBox()
            threshold_box.setRange(0, 1_000_000)
            threshold_box.setValue(rule.threshold)
            self.table.setCellWidget(row_index, 5, threshold_box)

            window_box = QSpinBox()
            window_box.setRange(0, 86_400)
            window_box.setValue(rule.time_window)
            self.table.setCellWidget(row_index, 6, window_box)

            description_item = QTableWidgetItem(rule.description)
            description_item.setToolTip(rule.description)
            self.table.setItem(row_index, 7, description_item)

            feedback = feedback_by_rule.get(rule.id, {})
            total = int(feedback.get("total", 0))
            confirmed = int(feedback.get("confirmed", 0))
            ignored = int(feedback.get("ignored", 0))
            confirmed_ratio = float(feedback.get("confirmed_ratio", 0.0))
            ignored_ratio = float(feedback.get("ignored_ratio", 0.0))
            feedback_text = f"Confirmed {confirmed_ratio:.0%}, ignored {ignored_ratio:.0%}" if total else "No alerts"
            tooltip = (
                f"Total alerts: {total}\nConfirmed: {confirmed}\nIgnored: {ignored}\n"
                f"Unconfirmed: {int(feedback.get('unconfirmed', 0))}"
            )
            self._set_feedback_item(row_index, 8, feedback_text, tooltip, ignored_ratio > 0.5 and total > 0)
            self._set_feedback_item(row_index, 9, str(total), tooltip, ignored_ratio > 0.5 and total > 0)
            self._set_feedback_item(row_index, 10, str(confirmed), tooltip, ignored_ratio > 0.5 and total > 0)
            self._set_feedback_item(row_index, 11, str(ignored), tooltip, ignored_ratio > 0.5 and total > 0)

        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 210)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 76)
        self.table.setColumnWidth(5, 105)
        self.table.setColumnWidth(6, 105)
        self.table.setColumnWidth(8, 190)
        self.table.setColumnWidth(9, 75)
        self.table.setColumnWidth(10, 95)
        self.table.setColumnWidth(11, 80)
        self.table.resizeRowsToContents()

    def _set_feedback_item(self, row: int, column: int, value: str, tooltip: str, warn: bool) -> None:
        item = QTableWidgetItem(value)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        item.setToolTip(
            f"{tooltip}\nIgnored ratio is above 50%; review thresholds or evidence." if warn else tooltip
        )
        if warn:
            item.setBackground(QColor("#fef3c7"))
        self.table.setItem(row, column, item)

    def _render_custom_rules(self) -> None:
        self.custom_table.setRowCount(len(self.current_custom_rules))
        for row_index, rule in enumerate(self.current_custom_rules):
            self._set_custom_row(row_index, rule)
        self.custom_table.setColumnWidth(0, 60)
        self.custom_table.setColumnWidth(1, 180)
        self.custom_table.setColumnWidth(2, 115)
        self.custom_table.setColumnWidth(3, 76)
        self.custom_table.setColumnWidth(4, 110)
        self.custom_table.setColumnWidth(5, 140)
        self.custom_table.setColumnWidth(6, 150)
        self.custom_table.setColumnWidth(7, 115)
        self.custom_table.setColumnWidth(8, 130)
        self.custom_table.setColumnWidth(9, 150)
        self.custom_table.resizeRowsToContents()

    def _set_custom_row(self, row: int, rule: CustomRuleRecord) -> None:
        id_item = QTableWidgetItem("" if rule.id is None else str(rule.id))
        id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
        self.custom_table.setItem(row, 0, id_item)
        self._set_text_item(self.custom_table, row, 1, rule.name)

        severity_box = QComboBox()
        severity_box.addItems(SEVERITY_OPTIONS)
        severity_box.setCurrentText(rule.severity.upper())
        self.custom_table.setCellWidget(row, 2, severity_box)

        enabled_box = QCheckBox()
        enabled_box.setChecked(rule.enabled)
        self.custom_table.setCellWidget(row, 3, enabled_box)

        protocol_box = QComboBox()
        protocol_box.addItems(PROTOCOL_OPTIONS)
        protocol_box.setCurrentText(rule.protocol if rule.protocol in PROTOCOL_OPTIONS else "Any")
        self.custom_table.setCellWidget(row, 4, protocol_box)

        self.custom_table.setCellWidget(row, 5, self._ip_box(rule.src_ip, self.source_ip_options, "source"))
        self.custom_table.setCellWidget(row, 6, self._ip_box(rule.dst_ip, self.destination_ip_options, "destination"))
        self.custom_table.setCellWidget(row, 7, self._port_box(rule.src_port))
        self.custom_table.setCellWidget(row, 8, self._port_box(rule.dst_port))
        self._set_text_item(self.custom_table, row, 9, rule.keyword or "")
        self._set_text_item(self.custom_table, row, 10, rule.description)

    def add_custom_rule_row(self) -> None:
        row = self.custom_table.rowCount()
        self.custom_table.setRowCount(row + 1)
        self._set_custom_row(
            row,
            CustomRuleRecord(name="New custom rule", severity="LOW", enabled=True, description="Matched custom rule conditions"),
        )

    def delete_selected_custom_rule(self) -> None:
        row = self.custom_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No rule selected", "Please select a custom rule first.")
            return
        rule_id = self._item_text(self.custom_table, row, 0)
        if rule_id:
            self.custom_rule_repository.delete(int(rule_id))
        self.custom_table.removeRow(row)
        QMessageBox.information(self, "Deleted", "The selected custom rule has been deleted.")
        self.refresh()

    def save_rules(self) -> None:
        self._save_builtin_rules()
        self._save_custom_rules()
        QMessageBox.information(self, "Saved", "Rule configuration saved. Future imports and live capture will use it.")
        self.refresh()

    def _save_builtin_rules(self) -> None:
        for row, original in enumerate(self.current_rules):
            enabled_widget = self.table.cellWidget(row, 4)
            threshold_widget = self.table.cellWidget(row, 5)
            window_widget = self.table.cellWidget(row, 6)
            description_item = self.table.item(row, 7)
            updated = RuleRecord(
                id=original.id,
                name=original.name,
                category=original.category,
                severity=original.severity,
                enabled=enabled_widget.isChecked() if isinstance(enabled_widget, QCheckBox) else original.enabled,
                threshold=threshold_widget.value() if isinstance(threshold_widget, QSpinBox) else original.threshold,
                time_window=window_widget.value() if isinstance(window_widget, QSpinBox) else original.time_window,
                description=description_item.text() if description_item else original.description,
            )
            self.rule_repository.update_rule(updated)

    def _save_custom_rules(self) -> None:
        for row in range(self.custom_table.rowCount()):
            name = self._item_text(self.custom_table, row, 1).strip()
            if not name:
                continue
            severity_widget = self.custom_table.cellWidget(row, 2)
            enabled_widget = self.custom_table.cellWidget(row, 3)
            protocol_widget = self.custom_table.cellWidget(row, 4)
            src_port_widget = self.custom_table.cellWidget(row, 7)
            dst_port_widget = self.custom_table.cellWidget(row, 8)
            protocol = protocol_widget.currentText() if isinstance(protocol_widget, QComboBox) else "Any"
            rule = CustomRuleRecord(
                id=self._optional_int(self._item_text(self.custom_table, row, 0)),
                name=name,
                severity=severity_widget.currentText() if isinstance(severity_widget, QComboBox) else "LOW",
                enabled=enabled_widget.isChecked() if isinstance(enabled_widget, QCheckBox) else True,
                protocol=None if protocol == "Any" else protocol,
                src_ip=self._optional_ip(self._combo_text(self.custom_table, row, 5)),
                dst_ip=self._optional_ip(self._combo_text(self.custom_table, row, 6)),
                src_port=self._spin_optional_value(src_port_widget),
                dst_port=self._spin_optional_value(dst_port_widget),
                keyword=self._optional_text(self._item_text(self.custom_table, row, 9)),
                description=self._item_text(self.custom_table, row, 10) or "Matched custom rule conditions",
            )
            if rule.id is None:
                self.custom_rule_repository.add(rule)
            else:
                self.custom_rule_repository.update(rule)

    def restore_defaults(self) -> None:
        self.rule_repository.reset_defaults()
        QMessageBox.information(self, "Restored", "Default rules have been restored.")
        self.refresh()

    def save_blacklist(self) -> None:
        self.blacklist_repository.save_all(self.blacklist_editor.toPlainText().splitlines())
        QMessageBox.information(self, "Saved", "Blacklisted IP addresses saved.")
        self.refresh()

    def add_enforced_block(self) -> None:
        labels = ["Source IP", "Destination IP", "Source Port", "Destination Port"]
        label, accepted = QInputDialog.getItem(self, "Add enforced block", "Field", labels, 0, False)
        if not accepted:
            return
        field = {
            "Source IP": "SRC_IP",
            "Destination IP": "DST_IP",
            "Source Port": "SRC_PORT",
            "Destination Port": "DST_PORT",
        }[label]
        value, accepted = QInputDialog.getText(self, "Add enforced block", "IP address or port")
        if not accepted or not value.strip():
            return
        protocol = "ANY"
        if field.endswith("PORT"):
            protocol, accepted = QInputDialog.getItem(self, "Port protocol", "Protocol", ["ANY", "TCP", "UDP"], 0, False)
            if not accepted:
                return
        try:
            _entry, result = self.blocklist_service.add_and_enforce(
                kind="IP" if field.endswith("IP") else "PORT",
                value=value.strip(),
                field=field,
                protocol=protocol,
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid blocklist value", str(exc))
            return
        self._show_enforcement_result(result.status, result.message, result.success)
        self.refresh()

    def remove_enforced_block(self) -> None:
        entry_id = self._selected_enforced_block_id()
        if entry_id is None:
            QMessageBox.information(self, "No block selected", "Please select an enforced block first.")
            return
        result = self.blocklist_service.remove(entry_id)
        self._show_enforcement_result(result.status, result.message, result.success)
        self.refresh()

    def retry_enforcement(self) -> None:
        entry_id = self._selected_enforced_block_id()
        if entry_id is None:
            QMessageBox.information(self, "No block selected", "Please select an enforced block first.")
            return
        result = self.blocklist_service.retry(entry_id)
        self._show_enforcement_result(result.status, result.message, result.success)
        self.refresh()

    def _selected_enforced_block_id(self) -> int | None:
        row = self.enforced_blocklist_table.currentRow()
        item = self.enforced_blocklist_table.item(row, 0) if row >= 0 else None
        value = item.data(Qt.UserRole) if item else None
        return int(value) if value is not None else None

    def _show_enforcement_result(self, status: str, message: str, success: bool) -> None:
        text = f"Enforcement status: {status}."
        if message:
            text += f"\n\n{message}"
        if success:
            QMessageBox.information(self, "Enforcement updated", text)
        else:
            QMessageBox.warning(self, "Enforcement unavailable", text)

    def _configure_table(
        self,
        table: QTableWidget,
        *,
        stretch_columns: tuple[int, ...],
        resize_to_contents_columns: tuple[int, ...],
    ) -> None:
        configure_responsive_table(
            table,
            stretch_columns=stretch_columns,
            resize_to_contents_columns=resize_to_contents_columns,
        )
        table.setWordWrap(False)

    def _set_text_item(self, table: QTableWidget, row: int, column: int, value: str) -> None:
        item = QTableWidgetItem(value)
        item.setToolTip(value)
        table.setItem(row, column, item)

    def _refresh_ip_options(self) -> None:
        source_ips: list[str] = []
        destination_ips: list[str] = []
        try:
            packets = self.packet_repository.list_recent(limit=2000)
        except Exception:
            packets = []

        for packet in packets:
            if packet.src_ip and packet.src_ip not in source_ips:
                source_ips.append(packet.src_ip)
            if packet.dst_ip and packet.dst_ip not in destination_ips:
                destination_ips.append(packet.dst_ip)

        for rule in self.current_custom_rules:
            if rule.src_ip and rule.src_ip not in source_ips:
                source_ips.append(rule.src_ip)
            if rule.dst_ip and rule.dst_ip not in destination_ips:
                destination_ips.append(rule.dst_ip)

        self.source_ip_options = ["Any", *source_ips[:40]]
        self.destination_ip_options = ["Any", *destination_ips[:40]]

    def _ip_box(self, value: str | None, options: list[str], role: str) -> QComboBox:
        box = QComboBox()
        box.setEditable(True)
        box.setInsertPolicy(QComboBox.NoInsert)
        box.addItems(options)
        box.setCurrentText(value or "Any")
        box.setToolTip(f"Choose a recent {role} IP, select Any, or type a custom IP.")
        return box

    def _port_box(self, value: int | None) -> QSpinBox:
        box = QSpinBox()
        box.setRange(0, 65535)
        box.setSpecialValueText("Any")
        box.setValue(value or 0)
        return box

    def _spin_optional_value(self, widget: QWidget | None) -> int | None:
        if isinstance(widget, QSpinBox):
            return None if widget.value() == 0 else widget.value()
        return None

    def _combo_text(self, table: QTableWidget, row: int, column: int) -> str:
        widget = table.cellWidget(row, column)
        if isinstance(widget, QComboBox):
            return widget.currentText().strip()
        return self._item_text(table, row, column)

    def _item_text(self, table: QTableWidget, row: int, column: int) -> str:
        item = table.item(row, column)
        return item.text().strip() if item else ""

    def _optional_text(self, value: str) -> str | None:
        value = value.strip()
        return value or None

    def _optional_ip(self, value: str) -> str | None:
        value = value.strip()
        if not value or value.lower() == "any":
            return None
        return value

    def _optional_int(self, value: str) -> int | None:
        value = value.strip()
        return int(value) if value.isdigit() else None
