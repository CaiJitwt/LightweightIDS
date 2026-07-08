from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

from models import AlertRecord


class AlertTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(["时间", "等级", "类型", "规则名称", "源 IP", "目标 IP", "描述", "状态"])
        self.horizontalHeader().setStretchLastSection(True)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

    def set_alerts(self, alerts: list[AlertRecord]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(len(alerts))

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
                if column == 0 and alert.id is not None:
                    item.setData(Qt.UserRole, alert.id)
                self.setItem(row, column, item)

        self.setSortingEnabled(True)

    def selected_alert_id(self) -> int | None:
        selected_items = self.selectedItems()
        if not selected_items:
            return None

        row = selected_items[0].row()
        item = self.item(row, 0)
        if item is None:
            return None

        value = item.data(Qt.UserRole)
        return int(value) if value is not None else None
