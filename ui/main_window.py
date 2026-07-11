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
from models import AlertRecord
from storage.database import Database
from ui.theme_manager import ThemeManager
from ui.alert_page import AlertPage
from ui.assets_page import AssetsPage
from ui.dashboard_page import DashboardPage
from ui.host_explorer_page import HostExplorerPage
from ui.investigations_page import InvestigationsPage
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
        self.page_titles = dict(PAGE_TITLES)
        self.page_keys = list(PAGE_TITLES.keys())

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
        self.dashboard_page = DashboardPage(self.database)
        self.packet_page = PacketPage(self.database)
        self.host_explorer_page = HostExplorerPage(self.database)
        self.alert_page = AlertPage(self.database)
        self.investigations_page = InvestigationsPage(self.database)
        self.assets_page = AssetsPage(self.database)
        self.page_by_key = {
            "dashboard": self.dashboard_page,
            "packets": self.packet_page,
            "hosts": self.host_explorer_page,
            "alerts": self.alert_page,
            "investigations": self.investigations_page,
            "assets": self.assets_page,
            "rules": RulePage(self.database),
            "reports": ReportPage(self.database),
            "settings": SettingsPage(self.database, self.config),
            "personalization": PersonalizationPage(self.theme_manager, self.overlay_pet),
        }

        for key in self.page_keys:
            page = self.page_by_key[key]
            item = QListWidgetItem(self.page_titles[key])
            item.setData(Qt.UserRole, key)
            self.nav_list.addItem(item)
            self.stack.addWidget(page)

        self.dashboard_page.host_activated.connect(lambda host_ip: self.navigate_to("hosts", host_ip))
        self.alert_page.investigation_requested.connect(self._add_alert_to_investigation)
        self.host_explorer_page.investigation_requested.connect(self._create_host_investigation)
        self.assets_page.assets_changed.connect(self.host_explorer_page.refresh)
        self.assets_page.assets_changed.connect(self.dashboard_page.refresh)

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

    def navigate_to(self, page_key: str, context: object | None = None) -> None:
        if page_key not in self.page_by_key:
            raise KeyError(f"Unknown page: {page_key}")
        index = self.page_keys.index(page_key)
        self.nav_list.setCurrentRow(index)
        if page_key == "hosts" and isinstance(context, str):
            self.host_explorer_page.select_host(context)

    def _add_alert_to_investigation(self, alert: AlertRecord) -> None:
        self.navigate_to("investigations")
        self.investigations_page.add_alert(alert)

    def _create_host_investigation(self, host_ip: str, summary: str, alerts: list[AlertRecord]) -> None:
        self.navigate_to("investigations")
        self.investigations_page.create_for_host(host_ip, summary, alerts)

    def _apply_style(self) -> None:
        self.theme_manager.apply_default()

    def resizeEvent(self, event: object) -> None:
        self.theme_manager.refresh_background_layer()
        if self.overlay_pet:
            self.overlay_pet.reposition()
        super().resizeEvent(event)  # type: ignore[arg-type]

    def closeEvent(self, event: object) -> None:
        if not self.packet_page.shutdown():
            self.statusBar().showMessage("Waiting for the active traffic task to stop. Please close the window again.")
            event.ignore()  # type: ignore[attr-defined]
            return
        super().closeEvent(event)  # type: ignore[arg-type]
