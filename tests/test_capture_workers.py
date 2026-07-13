from __future__ import annotations

import pytest

from scripts.generate_demo_pcap import generate_demo_pcap
from storage.database import Database
from storage.repositories import AlertRepository, CustomRuleRepository, PacketRepository, RuleRepository
from ui.packet_page import PcapImportWorker

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
