from __future__ import annotations

import pytest

from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from parser.packet_parser import PacketParser
from scripts.generate_demo_pcap import generate_demo_pcap

pytest.importorskip("scapy.all")


def test_demo_pcap_generates_expected_detection_alerts(tmp_path):
    pcap_path = generate_demo_pcap(tmp_path / "demo_attack_chain.pcap")
    parser = PacketParser()
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)

    alerts = []
    for raw_packet in PcapLoader().load(pcap_path):
        alerts.extend(engine.process_packet(parser.parse(raw_packet)))

    rule_ids = {alert.rule_id for alert in alerts}
    assert {
        "HOST_SCAN",
        "SQL_INJECTION",
        "MALICIOUS_COMMAND",
        "TLS_FINGERPRINT",
        "LATERAL_MOVEMENT",
    } <= rule_ids
