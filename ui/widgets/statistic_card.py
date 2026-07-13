from __future__ import annotations

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout

from ui.styles import _is_dark_mode, statistic_card_style


class StatisticCard(QFrame):
    def __init__(self, title: str, value: str, *, tone: str = "neutral") -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setStyleSheet(statistic_card_style(tone))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)

        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")

        layout.addWidget(title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str | int) -> None:
        self.value_label.setText(str(value))
