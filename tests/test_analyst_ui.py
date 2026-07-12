from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from models import AssetRecord, PacketRecord
from storage.analyst_repositories import AssetRepository
from storage.database import Database
from storage.repositories import PacketRepository
from ui.main_window import MainWindow


def test_main_window_builds_analyst_pages_and_navigates_to_host(tmp_path):
    app = QApplication.instance() or QApplication([])
    database = Database(tmp_path / "ids.db")
    database.initialize()
    AssetRepository(database).save(
        AssetRecord(ip="10.0.0.10", display_name="Lab host", role="Server", importance=80)
    )
    PacketRepository(database).add(
        PacketRecord(
            timestamp="2026-07-11 10:00:00.000",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            protocol="TCP",
            length=60,
        )
    )
    window = MainWindow(database, {"ui": {}, "detection": {}, "logging": {}})

    titles = [window.nav_list.item(index).text() for index in range(window.nav_list.count())]
    assert titles == [
        "Dashboard",
        "Traffic Monitor",
        "Host Explorer",
        "Alert Center",
        "Investigations",
        "Assets",
        "Rule Management",
        "Reports",
        "Settings",
        "Personalization",
    ]

    window.dashboard_page.host_activated.emit("10.0.0.10")
    assert window.stack.currentWidget() is window.host_explorer_page
    assert window.host_explorer_page.current_host_ip == "10.0.0.10"
    window.navigate_to("assets")
    assert window.stack.currentWidget() is window.assets_page
    assert window.packet_page.shutdown()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_dashboard_auto_refresh_runs_only_while_visible(tmp_path):
    app = QApplication.instance() or QApplication([])
    database = Database(tmp_path / "ids.db")
    database.initialize()
    window = MainWindow(database, {"ui": {}, "detection": {}, "logging": {}})
    window.show()
    app.processEvents()

    assert window.dashboard_page.auto_refresh_timer.isActive()
    assert window.dashboard_page.auto_refresh_timer.interval() == 5_000

    window.navigate_to("alerts")
    app.processEvents()
    assert not window.dashboard_page.auto_refresh_timer.isActive()

    window.navigate_to("dashboard")
    app.processEvents()
    assert window.dashboard_page.auto_refresh_timer.isActive()
    window.dashboard_page.auto_refresh_checkbox.setChecked(False)
    assert not window.dashboard_page.auto_refresh_timer.isActive()

    assert window.packet_page.shutdown()
    window.close()
    window.deleteLater()
    app.processEvents()
