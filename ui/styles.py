from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QApplication, QHeaderView, QLabel, QSizePolicy, QTableWidget, QTableWidgetItem


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


def apply_dark_palette(app: QApplication) -> None:
    if not _is_dark_mode():
        return
    from PySide6.QtGui import QPalette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#1a1a2e"))
    palette.setColor(QPalette.WindowText, QColor("#e0e0e0"))
    palette.setColor(QPalette.Base, QColor("#252540"))
    palette.setColor(QPalette.AlternateBase, QColor("#2a2a45"))
    palette.setColor(QPalette.ToolTipBase, QColor("#252540"))
    palette.setColor(QPalette.ToolTipText, QColor("#e0e0e0"))
    palette.setColor(QPalette.Text, QColor("#e0e0e0"))
    palette.setColor(QPalette.Button, QColor("#2a2a45"))
    palette.setColor(QPalette.ButtonText, QColor("#e0e0e0"))
    palette.setColor(QPalette.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.Link, QColor("#60a5fa"))
    palette.setColor(QPalette.Highlight, QColor("#2d8cff"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)


def _build_dark_palette() -> "QPalette":
    from PySide6.QtGui import QPalette
    p = QPalette()
    p.setColor(QPalette.WindowText, QColor("#d0d0d8"))
    p.setColor(QPalette.Button, QColor("#353550"))
    p.setColor(QPalette.ButtonText, QColor("#d0d0d8"))
    p.setColor(QPalette.Base, QColor("#252540"))
    p.setColor(QPalette.AlternateBase, QColor("#2a2a45"))
    p.setColor(QPalette.Text, QColor("#d0d0d8"))
    p.setColor(QPalette.ToolTipBase, QColor("#353550"))
    p.setColor(QPalette.ToolTipText, QColor("#d0d0d8"))
    p.setColor(QPalette.BrightText, QColor("#ffffff"))
    p.setColor(QPalette.Highlight, QColor("#2d8cff"))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.Link, QColor("#60a5fa"))
    p.setColor(QPalette.Window, QColor("#1a1a2e"))
    return p


DARK_PALETTE = _build_dark_palette()


_SKIP_LABEL_NAMES = {"Brand", "NavList", "SectionTitle"}

def apply_label_colors(root: "QWidget") -> None:
    for widget in root.findChildren(QLabel):
        if widget.objectName() in _SKIP_LABEL_NAMES:
            continue
        if not widget.styleSheet():
            widget.setStyleSheet("color: #1f2933;")


def _is_dark_mode() -> bool:
    app = QApplication.instance()
    if app is not None:
        return app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    return False


def _global_text_style() -> str:
    if _is_dark_mode():
        return """
        QLabel {
            color: #d0d0d8;
        }
        """
    return """
    QLabel {
        color: #1f2933;
    }
    """


GLOBAL_APP_STYLE = _global_text_style()


def _app_style() -> str:
    if _is_dark_mode():
        return """
        QMainWindow {
            background: #1a1a2e;
        }
        #AppRoot {
            background: #1a1a2e;
        }
        #Sidebar {
            background: #0f0f1a;
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
            color: #b0b0c0;
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
            color: #f0f0f5;
            font-size: 24px;
            font-weight: 700;
        }
        QLabel#SectionTitle {
            color: #f0f0f5;
            font-weight: 700;
        }
        QLabel#PageHint {
            color: #9090a0;
            font-size: 14px;
        }
        QFrame#Card {
            background: #252540;
            border: 1px solid #3a3a50;
            border-radius: 8px;
        }
        QLabel#CardTitle {
            color: #9090a0;
            font-size: 13px;
        }
        QLabel#CardValue {
            color: #f0f0f5;
            font-size: 24px;
            font-weight: 700;
        }
        QTableWidget {
            background: #252540;
            alternate-background-color: #2a2a45;
            border: 1px solid #3a3a50;
            gridline-color: #353550;
            selection-background-color: #3b3b5c;
            selection-color: #e0e0e0;
        }
        QHeaderView::section {
            background: #2a2a45;
            color: #e0e0e0;
            border: none;
            border-right: 1px solid #3a3a50;
            border-bottom: 1px solid #3a3a50;
            padding: 6px;
            font-weight: 700;
        }
        QPushButton {
            background: #1a1a2e;
            color: #e0e0e0;
            border: 1px solid #3a3a50;
            padding: 4px 12px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background: #252540;
        }
        QPushButton:pressed {
            background: #0f0f1a;
        }
        QPushButton:disabled {
            color: #606070;
        }
        QComboBox,
        QSpinBox,
        QDoubleSpinBox,
        QLineEdit,
        QTextEdit,
        QPlainTextEdit {
            background: #252540;
            color: #e0e0e0;
            border: 1px solid #3a3a50;
        }
        QStatusBar {
            background: #1a1a2e;
            color: #9090a0;
        }
        """
    return """
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
    QLabel#CardTitle {
        color: #617083;
        font-size: 13px;
    }
    QLabel#CardValue {
        color: #1f2933;
        font-size: 24px;
        font-weight: 700;
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
    QComboBox,
    QSpinBox,
    QDoubleSpinBox,
    QLineEdit,
    QTextEdit,
    QPlainTextEdit {
        background: #ffffff;
        color: #1f2933;
        border: 1px solid #dde3ea;
    }
    QStatusBar {
        background: #f6f7f9;
        color: #617083;
    }
    """


DEFAULT_APP_STYLE = _app_style()


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
