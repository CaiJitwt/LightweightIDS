from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHeaderView,
    QHBoxLayout,
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
from storage.database import Database
from storage.repositories import BlacklistRepository, CustomRuleRepository, RuleRepository


PROTOCOL_OPTIONS = ["Any", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "DNS", "HTTP", "HTTPS", "TLS", "DHCP", "MDNS", "LLMNR", "NBNS", "NTP", "QUIC"]
SEVERITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class RulePage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.rule_repository = RuleRepository(database)
        self.custom_rule_repository = CustomRuleRepository(database)
        self.blacklist_repository = BlacklistRepository(PROJECT_ROOT / "config" / "blacklist.txt")
        self.current_rules: list[RuleRecord] = []
        self.current_custom_rules: list[CustomRuleRecord] = []

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        button_bar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.save_button = QPushButton("Save")
        self.restore_button = QPushButton("Restore defaults")
        self.add_custom_button = QPushButton("Add custom rule")
        self.delete_custom_button = QPushButton("Delete selected rule")
        self.save_blacklist_button = QPushButton("Save blacklist")
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

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Category", "Severity", "Enabled", "Threshold", "Window (s)", "Description"])
        self._configure_table(self.table)

        self.custom_table = QTableWidget(0, 11)
        self.custom_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Severity", "Enabled", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port", "Keyword", "Description"]
        )
        self._configure_table(self.custom_table)

        self.blacklist_editor = QTextEdit()
        self.blacklist_editor.setPlaceholderText("One IP address per line. Empty lines are ignored.")
        self.blacklist_editor.setMaximumHeight(100)

        builtin_label = QLabel("Built-in detection rules")
        custom_label = QLabel("Custom rules: empty fields mean no restriction. Use drop-downs for protocol and severity.")
        blacklist_label = QLabel("Blacklisted IP addresses")
        for label in [builtin_label, custom_label, blacklist_label]:
            label.setStyleSheet("font-weight: 700; color: #1f2933;")

        layout.addLayout(button_bar)
        layout.addWidget(builtin_label)
        layout.addWidget(self.table, 2)
        layout.addWidget(custom_label)
        layout.addWidget(self.custom_table, 3)
        layout.addWidget(blacklist_label)
        layout.addWidget(self.blacklist_editor)

        self.refresh_button.clicked.connect(self.refresh)
        self.save_button.clicked.connect(self.save_rules)
        self.restore_button.clicked.connect(self.restore_defaults)
        self.add_custom_button.clicked.connect(self.add_custom_rule_row)
        self.delete_custom_button.clicked.connect(self.delete_selected_custom_rule)
        self.save_blacklist_button.clicked.connect(self.save_blacklist)

        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        self.current_rules = self.rule_repository.list_all()
        self.current_custom_rules = self.custom_rule_repository.list_all()
        self._render_builtin_rules()
        self._render_custom_rules()
        self.blacklist_editor.setPlainText("\n".join(self.blacklist_repository.list_all()))

    def _render_builtin_rules(self) -> None:
        self.table.setRowCount(len(self.current_rules))
        for row_index, rule in enumerate(self.current_rules):
            for column_index, value in enumerate([rule.id, rule.name, rule.category, rule.severity]):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                item.setToolTip(value)
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

        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 210)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 76)
        self.table.setColumnWidth(5, 105)
        self.table.setColumnWidth(6, 105)
        self.table.resizeRowsToContents()

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

        self._set_text_item(self.custom_table, row, 5, rule.src_ip or "")
        self._set_text_item(self.custom_table, row, 6, rule.dst_ip or "")
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
                src_ip=self._optional_text(self._item_text(self.custom_table, row, 5)),
                dst_ip=self._optional_text(self._item_text(self.custom_table, row, 6)),
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

    def _configure_table(self, table: QTableWidget) -> None:
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)

    def _set_text_item(self, table: QTableWidget, row: int, column: int, value: str) -> None:
        item = QTableWidgetItem(value)
        item.setToolTip(value)
        table.setItem(row, column, item)

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

    def _item_text(self, table: QTableWidget, row: int, column: int) -> str:
        item = table.item(row, column)
        return item.text().strip() if item else ""

    def _optional_text(self, value: str) -> str | None:
        value = value.strip()
        return value or None

    def _optional_int(self, value: str) -> int | None:
        value = value.strip()
        return int(value) if value.isdigit() else None
