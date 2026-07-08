from __future__ import annotations

import pytest

from capture.pcap_loader import PcapLoader

scapy = pytest.importorskip("scapy.all")


def test_pcap_loader_reads_packets(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    packets = [
        scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(sport=10000, dport=80),
        scapy.IP(src="192.168.1.11", dst="192.168.1.21") / scapy.UDP(sport=10001, dport=53),
    ]
    scapy.wrpcap(str(pcap_path), packets)

    loaded_packets = list(PcapLoader().load(pcap_path))

    assert len(loaded_packets) == 2
