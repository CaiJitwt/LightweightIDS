from __future__ import annotations

import pytest

from scripts.generate_demo_pcap import generate_demo_pcap
from storage.database import Database
from storage.repositories import AlertRepository, CustomRuleRepository, PacketRepository, RuleRepository
from ui import packet_page
from ui.packet_page import LiveCaptureWorker, PcapImportWorker

pytest.importorskip("scapy.all")


def test_pcap_worker_can_detect_without_persisting_packet_rows(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    pcap_path = generate_demo_pcap(tmp_path / "demo_attack_chain.pcap")
    batches: list[tuple[int, int]] = []
    finished: list[tuple[int, int, int]] = []

    worker = PcapImportWorker(
        pcap_path,
        RuleRepository(database).list_all(),
        CustomRuleRepository(database).list_all(),
        database,
        batch_size=10,
        save_packets=False,
        alert_cooldown_seconds=0,
    )
    worker.batch_processed.connect(
        lambda packets, alerts, saved_packets, saved_alerts: batches.append(
            (saved_packets, saved_alerts)
        )
    )
    worker.import_finished.connect(
        lambda packet_total, alert_total, skipped_total: finished.append(
            (packet_total, alert_total, skipped_total)
        )
    )

    worker.run()

    assert finished
    assert finished[0][0] > 0
    assert finished[0][1] > 0
    assert finished[0][2] == 0
    assert PacketRepository(database).count() == 0
    assert AlertRepository(database).count() == sum(saved_alerts for _, saved_alerts in batches)


def test_live_capture_worker_flushes_pending_alerts_when_capture_stops(tmp_path, monkeypatch):
    from scapy.all import IP, Raw, TCP

    database = Database(tmp_path / "ids.db")
    database.initialize()
    request = (
        b"POST /login HTTP/1.1\r\nHost: demo.test\r\n\r\n"
        b"username=admin&password=1%27+UNION+SELECT+password+FROM+users--"
    )
    raw_packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=51_000,
        dport=8080,
        flags="PA",
    ) / Raw(load=request)

    class OnePacketCapture:
        def __init__(self, **kwargs):
            self.packet_callback = kwargs["packet_callback"]
            self._stop_event = type("StopState", (), {"is_set": lambda self: False})()

        def start(self):
            self.packet_callback(raw_packet)

        def stop(self):
            return None

    monkeypatch.setattr(packet_page, "LiveCapture", OnePacketCapture)
    worker = LiveCaptureWorker(
        interface=None,
        rule_records=RuleRepository(database).list_all(),
        custom_rule_records=CustomRuleRepository(database).list_all(),
        database=database,
        batch_size=100,
        flush_interval_seconds=60,
        alert_cooldown_seconds=0,
    )

    worker.run()

    assert PacketRepository(database).count() == 1
    assert {alert.rule_id for alert in AlertRepository(database).list_all()} >= {"SQL_INJECTION"}
