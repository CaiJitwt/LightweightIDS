from __future__ import annotations

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout


class StatisticCard(QFrame):
    def __init__(self, title: str, value: str) -> None:
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)

        title_label = QLabel(title)
        title_label.setStyleSheet("color: #617083; font-size: 13px;")
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("color: #1f2933; font-size: 24px; font-weight: 700;")

        layout.addWidget(title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str | int) -> None:
        self.value_label.setText(str(value))
