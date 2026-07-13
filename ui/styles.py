from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QSizePolicy, QTableWidget, QTableWidgetItem


@dataclass(frozen=True)
class SeverityStyle:
    background: str
    foreground: str


SEVERITY_STYLES: dict[str, SeverityStyle] = {
    "CRITICAL": SeverityStyle("#7f1d1d", "#ffffff"),
    "HIGH": SeverityStyle("#fee2e2", "#991b1b"),
    "MEDIUM": SeverityStyle("#fef3c7", "#92400e"),
    "LOW": SeverityStyle("#dbeafe", "#1e40af"),
    "INFO": SeverityStyle("#e5e7eb", "#374151"),
}


SEMANTIC_STYLES: dict[str, SeverityStyle] = {
    "CONFIRMED": SeverityStyle("#dcfce7", "#166534"),
    "UNCONFIRMED": SeverityStyle("#e0f2fe", "#075985"),
    "IGNORED": SeverityStyle("#f1f5f9", "#475569"),
    "OPEN": SeverityStyle("#dcfce7", "#166534"),
    "MONITORING": SeverityStyle("#e0f2fe", "#075985"),
    "CLOSED": SeverityStyle("#f1f5f9", "#475569"),
    "ENFORCED": SeverityStyle("#dcfce7", "#166534"),
    "PENDING": SeverityStyle("#fef3c7", "#92400e"),
    "FAILED": SeverityStyle("#fee2e2", "#991b1b"),
    "REMOVED": SeverityStyle("#f1f5f9", "#475569"),
    "WORKSTATION": SeverityStyle("#e0f2fe", "#075985"),
    "SERVER": SeverityStyle("#ede9fe", "#5b21b6"),
    "DATABASE": SeverityStyle("#fae8ff", "#86198f"),
    "GATEWAY": SeverityStyle("#d1fae5", "#065f46"),
    "DOMAIN CONTROLLER": SeverityStyle("#fee2e2", "#991b1b"),
    "OTHER": SeverityStyle("#f1f5f9", "#475569"),
    "INBOUND": SeverityStyle("#e0f2fe", "#075985"),
    "OUTBOUND": SeverityStyle("#dcfce7", "#166534"),
    "HTTP": SeverityStyle("#dcfce7", "#166534"),
    "HTTPS": SeverityStyle("#ccfbf1", "#115e59"),
    "TLS": SeverityStyle("#ccfbf1", "#115e59"),
    "DNS": SeverityStyle("#ede9fe", "#5b21b6"),
    "TCP": SeverityStyle("#dbeafe", "#1e40af"),
    "UDP": SeverityStyle("#fef3c7", "#92400e"),
    "ICMP": SeverityStyle("#ffedd5", "#9a3412"),
}


def severity_tooltip(severity: str) -> str:
    """Return a localized tooltip for the given severity level."""
    from ui.i18n import tr
    return tr(f"severity.{severity.upper()}.tooltip")


def semantic_tooltip(key: str) -> str:
    """Return a localized tooltip for the given semantic key."""
    from ui.i18n import tr
    return tr(f"semantic.{key.strip().upper()}.tooltip")


CARD_TONES = {
    "blue": ("#eff6ff", "#2563eb"),
    "green": ("#f0fdf4", "#16a34a"),
    "amber": ("#fffbeb", "#d97706"),
    "red": ("#fef2f2", "#dc2626"),
    "violet": ("#f5f3ff", "#7c3aed"),
    "neutral": ("#ffffff", "#94a3b8"),
}


GLOBAL_APP_STYLE = """
QWidget {
    background-color: #f5f5f5;
    color: #202020;
}
QLabel,
QCheckBox,
QRadioButton,
QGroupBox {
    color: #202020;
}
QLineEdit,
QTextEdit,
QPlainTextEdit,
QComboBox,
QSpinBox,
QDoubleSpinBox,
QTableView,
QTreeView,
QListView {
    background-color: #ffffff;
    color: #202020;
    selection-background-color: #3478f6;
    selection-color: #ffffff;
}
QPushButton {
    background-color: #e6e6e6;
    color: #202020;
}
"""


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


def apply_severity_style(item: QTableWidgetItem, severity: str, tooltip: str | None = None) -> None:
    style = severity_style(severity)
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(tooltip if tooltip is not None else severity_tooltip(severity))


def apply_semantic_style(item: QTableWidgetItem, value: str, tooltip: str | None = None) -> bool:
    normalized = value.strip().upper()
    style = SEMANTIC_STYLES.get(normalized)
    if style is None:
        return False
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(tooltip if tooltip is not None else semantic_tooltip(normalized))
    return True


def apply_category_style(item: QTableWidgetItem, value: str) -> bool:
    normalized = value.strip().upper()
    if normalized in SEVERITY_STYLES:
        apply_severity_style(item, normalized)
        return True
    return apply_semantic_style(item, value)


def apply_score_style(item: QTableWidgetItem, score: float, *, label: str = "Risk score") -> None:
    from ui.i18n import tr
    if score >= 80:
        style = SeverityStyle("#fee2e2", "#991b1b")
        level_key = "score.HIGH"
    elif score >= 50:
        style = SeverityStyle("#ffedd5", "#9a3412")
        level_key = "score.ELEVATED"
    elif score >= 25:
        style = SeverityStyle("#fef3c7", "#92400e")
        level_key = "score.MODERATE"
    else:
        style = SeverityStyle("#dcfce7", "#166534")
        level_key = "score.LOW"
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(tr("score.format", score=score, tooltip=tr(level_key)))


def apply_importance_style(item: QTableWidgetItem, importance: int) -> None:
    from ui.i18n import tr
    if importance >= 80:
        style = SeverityStyle("#fee2e2", "#991b1b")
        level_key = "importance.HIGH"
    elif importance >= 50:
        style = SeverityStyle("#fef3c7", "#92400e")
        level_key = "importance.STANDARD"
    else:
        style = SeverityStyle("#e0f2fe", "#075985")
        level_key = "importance.LOW"
    item.setBackground(QColor(style.background))
    item.setForeground(QColor(style.foreground))
    item.setToolTip(tr("importance.format", importance=importance, tooltip=tr(level_key)))


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
