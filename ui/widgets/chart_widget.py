from __future__ import annotations

from PySide6.QtWidgets import QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class ChartWidget(QWidget):
    def __init__(self, title: str = "图表") -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-weight: 700; color: #1f2933;")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["项目", "数量", "占比"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.title_label)
        layout.addWidget(self.table)

    def set_data(self, data: dict[str, int] | list[tuple[object, int]]) -> None:
        if isinstance(data, dict):
            rows = list(data.items())
        else:
            rows = [(str(key), value) for key, value in data]

        total = sum(int(value) for _, value in rows)
        self.table.setRowCount(len(rows))
        for row_index, (label, value) in enumerate(rows):
            percent = 0 if total == 0 else int(value) / total * 100
            values = [str(label), str(value), f"{percent:.1f}%"]
            for column_index, text in enumerate(values):
                self.table.setItem(row_index, column_index, QTableWidgetItem(text))
