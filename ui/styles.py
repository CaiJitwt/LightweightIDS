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


SEMANTIC_STYLES = {
    "CONFIRMED": SeverityStyle("#dcfce7", "#166534", "Confirmed by an analyst"),
    "UNCONFIRMED": SeverityStyle("#e0f2fe", "#075985", "Awaiting analyst review"),
    "IGNORED": SeverityStyle("#f1f5f9", "#475569", "Marked as ignored"),
    "OPEN": SeverityStyle("#dcfce7", "#166534", "Open investigation"),
    "MONITORING": SeverityStyle("#e0f2fe", "#075985", "Investigation under monitoring"),
    "CLOSED": SeverityStyle("#f1f5f9", "#475569", "Closed investigation"),
    "ENFORCED": SeverityStyle("#dcfce7", "#166534", "Traffic block is enforced"),
    "PENDING": SeverityStyle("#fef3c7", "#92400e", "Waiting for enforcement"),
    "FAILED": SeverityStyle("#fee2e2", "#991b1b", "Enforcement failed"),
    "REMOVED": SeverityStyle("#f1f5f9", "#475569", "Traffic block was removed"),
    "WORKSTATION": SeverityStyle("#e0f2fe", "#075985", "Workstation asset"),
    "SERVER": SeverityStyle("#ede9fe", "#5b21b6", "Server asset"),
    "DATABASE": SeverityStyle("#fae8ff", "#86198f", "Database asset"),
    "GATEWAY": SeverityStyle("#d1fae5", "#065f46", "Gateway asset"),
    "DOMAIN CONTROLLER": SeverityStyle("#fee2e2", "#991b1b", "Domain controller asset"),
    "OTHER": SeverityStyle("#f1f5f9", "#475569", "Other asset role"),
    "INBOUND": SeverityStyle("#e0f2fe", "#075985", "Inbound traffic"),
    "OUTBOUND": SeverityStyle("#dcfce7", "#166534", "Outbound traffic"),
    "HTTP": SeverityStyle("#dcfce7", "#166534", "Plaintext HTTP traffic"),
    "HTTPS": SeverityStyle("#ccfbf1", "#115e59", "HTTPS traffic; payload remains encrypted"),
    "TLS": SeverityStyle("#ccfbf1", "#115e59", "TLS metadata traffic"),
    "DNS": SeverityStyle("#ede9fe", "#5b21b6", "DNS traffic"),
    "TCP": SeverityStyle("#dbeafe", "#1e40af", "TCP traffic"),
    "UDP": SeverityStyle("#fef3c7", "#92400e", "UDP traffic"),
    "ICMP": SeverityStyle("#ffedd5", "#9a3412", "ICMP traffic"),
}


CARD_TONES = {
    "blue": ("#eff6ff", "#2563eb"),
    "green": ("#f0fdf4", "#16a34a"),
    "amber": ("#fffbeb", "#d97706"),
    "red": ("#fef2f2", "#dc2626"),
    "violet": ("#f5f3ff", "#7c3aed"),
    "neutral": ("#ffffff", "#94a3b8"),
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


def apply_semantic_style(item: QTableWidgetItem, value: str, tooltip: str | None = None) -> bool:
    style = SEMANTIC_STYLES.get(value.strip().upper())
    if style is None:
        return False
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(tooltip or style.tooltip)
    return True


def apply_category_style(item: QTableWidgetItem, value: str) -> bool:
    normalized = value.strip().upper()
    if normalized in SEVERITY_STYLES:
        apply_severity_style(item, normalized)
        return True
    return apply_semantic_style(item, value)


def apply_score_style(item: QTableWidgetItem, score: float, *, label: str = "Risk score") -> None:
    if score >= 80:
        style = SeverityStyle("#fee2e2", "#991b1b", "High risk")
    elif score >= 50:
        style = SeverityStyle("#ffedd5", "#9a3412", "Elevated risk")
    elif score >= 25:
        style = SeverityStyle("#fef3c7", "#92400e", "Moderate risk")
    else:
        style = SeverityStyle("#dcfce7", "#166534", "Low risk")
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(f"{label}: {score:g}. {style.tooltip}.")


def apply_importance_style(item: QTableWidgetItem, importance: int) -> None:
    if importance >= 80:
        style = SeverityStyle("#fee2e2", "#991b1b", "High-value asset")
    elif importance >= 50:
        style = SeverityStyle("#fef3c7", "#92400e", "Standard-priority asset")
    else:
        style = SeverityStyle("#e0f2fe", "#075985", "Lower-priority asset")
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(f"Asset importance: {importance}. {style.tooltip}.")


def statistic_card_style(tone: str) -> str:
    background, accent = CARD_TONES.get(tone, CARD_TONES["neutral"])
    return (
        "QFrame#Card {"
        f"background: {background}; border: 1px solid #dde3ea; "
        f"border-left: 4px solid {accent}; border-radius: 8px;"
        "}"
    )


def severity_style(severity: str) -> SeverityStyle:
    return SEVERITY_STYLES.get(severity.upper(), SEVERITY_STYLES["INFO"])
