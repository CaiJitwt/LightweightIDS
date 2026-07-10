from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QSizePolicy, QTableWidget, QTableWidgetItem


@dataclass(frozen=True)
class SeverityStyle:
    background: str
    foreground: str
    tooltip: str


SEVERITY_STYLES = {
    "CRITICAL": SeverityStyle("#7f1d1d", "#ffffff", "Critical severity alert"),
    "HIGH": SeverityStyle("#fee2e2", "#991b1b", "High severity alert"),
    "MEDIUM": SeverityStyle("#fef3c7", "#92400e", "Medium severity alert"),
    "LOW": SeverityStyle("#dbeafe", "#1e40af", "Low severity alert"),
    "INFO": SeverityStyle("#e5e7eb", "#374151", "Informational alert"),
}


DEFAULT_APP_STYLE = """
QMainWindow {
    background: #f6f7f9;
}
#AppRoot {
    background: #f6f7f9;
}
#Sidebar {
    background: #17202a;
    border: none;
}
#Brand {
    color: #ffffff;
    font-size: 20px;
    font-weight: 700;
}
#NavList {
    background: transparent;
    border: none;
    color: #d7dde6;
    font-size: 14px;
    outline: 0;
}
#NavList::item {
    height: 40px;
    padding-left: 10px;
    border-radius: 6px;
}
#NavList::item:selected {
    background: #2d8cff;
    color: #ffffff;
}
#PageTitle {
    color: #1f2933;
    font-size: 24px;
    font-weight: 700;
}
QLabel#SectionTitle {
    color: #1f2933;
    font-weight: 700;
}
QLabel#PageHint {
    color: #617083;
    font-size: 14px;
}
QFrame#Card {
    background: #ffffff;
    border: 1px solid #dde3ea;
    border-radius: 8px;
}
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f8fafc;
    border: 1px solid #dde3ea;
    gridline-color: #e5e7eb;
    selection-background-color: #dbeafe;
    selection-color: #111827;
}
QHeaderView::section {
    background: #edf2f7;
    color: #1f2933;
    border: none;
    border-right: 1px solid #dde3ea;
    border-bottom: 1px solid #d5dde7;
    padding: 6px;
    font-weight: 700;
}
"""


def configure_responsive_table(
    table: QTableWidget,
    *,
    stretch_columns: tuple[int, ...] = (),
    resize_to_contents_columns: tuple[int, ...] = (),
    min_section_size: int = 56,
) -> None:
    table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    header = table.horizontalHeader()
    header.setMinimumSectionSize(min_section_size)
    header.setSectionResizeMode(QHeaderView.Interactive)
    header.setStretchLastSection(True)
    for column in resize_to_contents_columns:
        header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
    for column in stretch_columns:
        header.setSectionResizeMode(column, QHeaderView.Stretch)


def apply_severity_style(item: QTableWidgetItem, severity: str) -> None:
    style = severity_style(severity)
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(style.tooltip)


def severity_style(severity: str) -> SeverityStyle:
    return SEVERITY_STYLES.get(severity.upper(), SEVERITY_STYLES["INFO"])
