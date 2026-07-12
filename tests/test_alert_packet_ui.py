from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from models import AlertRecord, PacketRecord
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository
from ui.alert_page import AlertPage
from ui.rule_page import RulePage


def test_alert_page_renders_related_packet_list_and_rule_page_blocklist(tmp_path):
    app = QApplication.instance() or QApplication([])
    database = Database(tmp_path / "ids.db")
    database.initialize()
    packet = PacketRecord(
        timestamp="2026-07-12 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="HTTP",
        length=100,
        raw_summary="GET /?q=union select",
    )
    PacketRepository(database).add(packet)
    AlertRepository(database).add(
        AlertRecord(
            timestamp=packet.timestamp,
            rule_id="SQL_INJECTION",
            rule_name="SQL injection detection",
            alert_type="SQL_INJECTION",
            severity="CRITICAL",
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            description="SQL injection indicator",
            evidence="union select",
        )
    )
    alert_page = AlertPage(database)
    rule_page = RulePage(database)
    alert_page.table.selectRow(0)
    alert_page.render_selected_alert_detail()
    assert alert_page.related_packets_table.rowCount() == 1
    assert alert_page.related_title.text() == "Related packets (1)"
    assert rule_page.enforced_blocklist_table.columnCount() == 8
    alert_page.deleteLater()
    rule_page.deleteLater()
    app.processEvents()

