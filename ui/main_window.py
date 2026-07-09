from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QSizePolicy,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from app.constants import APP_NAME, PAGE_TITLES
from storage.database import Database
from ui.alert_page import AlertPage
from ui.dashboard_page import DashboardPage
from ui.packet_page import PacketPage
from ui.report_page import ReportPage
from ui.rule_page import RulePage
from ui.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config
        self.page_keys = list(PAGE_TITLES.keys())

        ui_config = config.get("ui", {})
        self.setWindowTitle(APP_NAME)
        self.resize(int(ui_config.get("window_width", 1180)), int(ui_config.get("window_height", 760)))

        self.title_label = QLabel(PAGE_TITLES["dashboard"])
        self.title_label.setObjectName("PageTitle")

        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(180)
        self.nav_list.setObjectName("NavList")

        self.stack = QStackedWidget()
        self._build_pages()
        self._build_layout()
        self._apply_style()

        self.nav_list.currentRowChanged.connect(self._switch_page)
        self.nav_list.setCurrentRow(0)

        status_bar = QStatusBar()
        status_bar.showMessage(f"System ready. Database: {self.database.path}")
        self.setStatusBar(status_bar)

    def _build_pages(self) -> None:
        pages = [
            DashboardPage(self.database),
            PacketPage(self.database),
            AlertPage(self.database),
            RulePage(self.database),
            ReportPage(self.database),
            SettingsPage(self.database, self.config),
        ]

        for key, page in zip(self.page_keys, pages, strict=True):
            item = QListWidgetItem(PAGE_TITLES[key])
            item.setData(Qt.UserRole, key)
            self.nav_list.addItem(item)
            self.stack.addWidget(page)

    def _build_layout(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 18, 16, 16)
        sidebar_layout.setSpacing(14)

        brand = QLabel(APP_NAME)
        brand.setObjectName("Brand")
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(self.nav_list)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 20, 24, 20)
        content_layout.setSpacing(18)
        content_layout.addWidget(self.title_label)
        content_layout.addWidget(self.stack)
        content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        root_layout.addWidget(sidebar)
        root_layout.addWidget(content)
        self.setCentralWidget(root)

    def _switch_page(self, index: int) -> None:
        if index < 0:
            return
        key = self.nav_list.item(index).data(Qt.UserRole)
        self.title_label.setText(PAGE_TITLES[key])
        self.stack.setCurrentIndex(index)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
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
            QLabel#PageHint {
                color: #617083;
                font-size: 14px;
            }
            QFrame#Card {
                background: #ffffff;
                border: 1px solid #dde3ea;
                border-radius: 8px;
            }
            """
        )
