from __future__ import annotations

from PySide6.QtWidgets import QLabel, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ui.styles import configure_responsive_table


class ChartWidget(QWidget):
    def __init__(self, title: str = "Chart") -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("SectionTitle")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Item", "Value", "Percent"])
        configure_responsive_table(self.table, stretch_columns=(0,), resize_to_contents_columns=(1, 2))
        self.table.setMinimumHeight(120)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.title_label)
        layout.addWidget(self.table, 1)

    def set_data(self, data: dict[str, int] | list[tuple[object, int]]) -> None:
        if isinstance(data, dict):
            rows = list(data.items())
        else:
            rows = [(str(key), value) for key, value in data]

        rows = rows[:20]
        total = sum(int(value) for _, value in rows)
        self.table.setRowCount(len(rows))
        for row_index, (label, value) in enumerate(rows):
            percent = 0 if total == 0 else int(value) / total * 100
            values = [str(label), str(value), f"{percent:.1f}%"]
            for column_index, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row_index, column_index, item)
