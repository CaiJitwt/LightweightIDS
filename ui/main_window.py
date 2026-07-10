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
from ui.theme_manager import ThemeManager
from ui.alert_page import AlertPage
from ui.dashboard_page import DashboardPage
from ui.packet_page import PacketPage
from ui.personalization_page import PersonalizationPage
from ui.report_page import ReportPage
from ui.rule_page import RulePage
from ui.settings_page import SettingsPage
from ui.widgets.overlay_pet_widget import OverlayPetWidget


class MainWindow(QMainWindow):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config
        self.page_titles = {**PAGE_TITLES, "personalization": "Personalization"}
        self.page_keys = list(PAGE_TITLES.keys()) + ["personalization"]

        ui_config = config.get("ui", {})
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1000, 650)
        self.resize(int(ui_config.get("window_width", 1180)), int(ui_config.get("window_height", 760)))

        self.title_label = QLabel(PAGE_TITLES["dashboard"])
        self.title_label.setObjectName("PageTitle")

        self.nav_list = QListWidget()
        self.nav_list.setMinimumWidth(168)
        self.nav_list.setMaximumWidth(220)
        self.nav_list.setObjectName("NavList")

        self.stack = QStackedWidget()
        self.theme_manager = ThemeManager(self)
        self.overlay_pet: OverlayPetWidget | None = None
        self._build_layout()
        self._build_pages()
        self._apply_style()

        self.nav_list.currentRowChanged.connect(self._switch_page)
        self.nav_list.setCurrentRow(0)

        status_bar = QStatusBar()
        status_bar.showMessage(f"System ready. Database: {self.database.path}")
        self.setStatusBar(status_bar)

    def _build_pages(self) -> None:
        if self.overlay_pet is None:
            raise RuntimeError("Overlay pet widget must be created before pages are built.")
        pages = [
            DashboardPage(self.database),
            PacketPage(self.database),
            AlertPage(self.database),
            RulePage(self.database),
            ReportPage(self.database),
            SettingsPage(self.database, self.config),
            PersonalizationPage(self.theme_manager, self.overlay_pet),
        ]

        for key, page in zip(self.page_keys, pages, strict=True):
            item = QListWidgetItem(self.page_titles[key])
            item.setData(Qt.UserRole, key)
            self.nav_list.addItem(item)
            self.stack.addWidget(page)

    def _build_layout(self) -> None:
        root = QWidget()
        root.setObjectName("AppRoot")
        background_layer = QLabel(root)
        background_layer.setObjectName("BackgroundLayer")
        self.theme_manager.attach_background_layer(background_layer)
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
        sidebar_layout.addWidget(self.nav_list, 1)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 20, 24, 20)
        content_layout.setSpacing(18)
        content_layout.addWidget(self.title_label)
        content_layout.addWidget(self.stack, 1)
        content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        root_layout.addWidget(sidebar, 0)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(root)
        self.overlay_pet = OverlayPetWidget(root)
        self.overlay_pet.raise_()

    def _switch_page(self, index: int) -> None:
        if index < 0:
            return
        key = self.nav_list.item(index).data(Qt.UserRole)
        self.title_label.setText(self.page_titles[key])
        self.stack.setCurrentIndex(index)

    def _apply_style(self) -> None:
        self.theme_manager.apply_default()

    def resizeEvent(self, event: object) -> None:
        self.theme_manager.refresh_background_layer()
        if self.overlay_pet:
            self.overlay_pet.reposition()
        super().resizeEvent(event)  # type: ignore[arg-type]
