from __future__ import annotations

import pytest

from capture.pcap_loader import PcapLoader
from detection.engine import DetectionEngine
from parser.packet_parser import PacketParser
from scripts.generate_demo_pcap import EXPECTED_DEMO_RULE_IDS, generate_demo_pcap

pytest.importorskip("scapy.all")


def test_demo_pcap_generates_expected_detection_alerts(tmp_path):
    pcap_path = generate_demo_pcap(tmp_path / "demo_attack_chain.pcap")
    parser = PacketParser()
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)

    alerts = []
    parsed_packets = []
    for raw_packet in PcapLoader().load(pcap_path):
        packet = parser.parse(raw_packet)
        parsed_packets.append(packet)
        alerts.extend(engine.process_packet(packet))

    rule_ids = {alert.rule_id for alert in alerts}
    assert EXPECTED_DEMO_RULE_IDS <= rule_ids
    assert all(
        packet.protocol == "HTTP" and packet.dst_port in {80, 8080}
        for packet in parsed_packets
        if packet.http_method
    )
