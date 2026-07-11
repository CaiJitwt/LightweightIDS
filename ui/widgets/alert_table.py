from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from models import AlertRecord
from ui.styles import apply_severity_style, configure_responsive_table, severity_style


class AlertTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(["Time", "Severity", "Type", "Rule", "Source IP", "Destination IP", "Description", "Status"])
        configure_responsive_table(self, stretch_columns=(2, 3, 6), resize_to_contents_columns=(1, 7))
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 160)
        self.setColumnWidth(1, 82)
        self.setColumnWidth(2, 150)
        self.setColumnWidth(3, 170)
        self.setColumnWidth(4, 120)
        self.setColumnWidth(5, 130)
        self.setColumnWidth(7, 96)

    def set_alerts(self, alerts: list[AlertRecord]) -> None:
        sorting_enabled = self.isSortingEnabled()
        self.setSortingEnabled(False)
        self.setUpdatesEnabled(False)
        self.setRowCount(len(alerts))

        try:
            for row, alert in enumerate(alerts):
                values = [
                    alert.timestamp,
                    alert.severity,
                    alert.alert_type,
                    alert.rule_name,
                    alert.src_ip or "",
                    alert.dst_ip or "",
                    alert.description,
                    alert.status,
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    if column == 1:
                        apply_severity_style(item, alert.severity)
                        item.setTextAlignment(Qt.AlignCenter)
                        item.setToolTip(f"{severity_style(alert.severity).tooltip}\n{alert.description}")
                    if alert.id is not None:
                        item.setData(Qt.UserRole, alert.id)
                    self.setItem(row, column, item)
        finally:
            self.setUpdatesEnabled(True)
            self.setSortingEnabled(sorting_enabled)

    def selected_alert_id(self) -> int | None:
        row = self.currentRow()
        if row < 0:
            selected_items = self.selectedItems()
            if not selected_items:
                return None
            row = selected_items[0].row()

        if row < 0:
            return None

        item = self.item(row, 0)
        if item is None:
            item = self.item(row, 1)
        if item is None:
            return None

        value = item.data(Qt.UserRole)
        return int(value) if value is not None else None

    def select_alert_id(self, alert_id: int) -> bool:
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item is not None and item.data(Qt.UserRole) == alert_id:
                self.selectRow(row)
                self.scrollToItem(item)
                return True
        return False
