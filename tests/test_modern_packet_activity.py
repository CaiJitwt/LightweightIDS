from __future__ import annotations

from modern_ui.capture_session import CaptureSessionService
from models import PacketRecord
from storage.database import Database


def test_imported_packet_activity_feed_pages_without_skipping_records(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    service = CaptureSessionService(database, max_event_records=1_000)
    packets = [
        PacketRecord(
            timestamp=f"2026-01-01 00:00:{index % 60:02d}.000",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=40_000 + index,
            dst_port=80,
            protocol="TCP",
            length=64,
        )
        for index in range(600)
    ]

    service.publish_import_batch(packets, [], saved_packets=600, saved_alerts=0)
    first = service.packets_since(0, limit=250)
    second = service.packets_since(first["nextSequence"], limit=250)
    third = service.packets_since(second["nextSequence"], limit=250)

    assert [len(first["records"]), len(second["records"]), len(third["records"])] == [250, 250, 100]
    assert third["nextSequence"] == 600
    assert service.status()["packetTotal"] == 600
