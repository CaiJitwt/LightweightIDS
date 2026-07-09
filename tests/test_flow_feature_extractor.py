from __future__ import annotations

from detection.features import FlowFeatureExtractor
from models import PacketRecord


def packet(
    *,
    second: int,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    dst_port: int = 80,
    protocol: str = "TCP",
    length: int = 100,
    tcp_flags: str | None = None,
    dns_query: str | None = None,
    http_path: str | None = None,
) -> PacketRecord:
    return PacketRecord(
        timestamp=f"2026-01-01 00:00:{second:02d}.000",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        http_method="GET" if http_path else None,
        http_host="example.test" if http_path else None,
        http_path=http_path,
    )


def test_flow_feature_extractor_aggregates_by_source_destination_and_window():
    features = FlowFeatureExtractor(time_window=60).extract(
        [
            packet(second=1, dst_ip="192.168.1.20", dst_port=80, length=100, http_path="/"),
            packet(second=2, dst_ip="192.168.1.20", dst_port=443, length=200, tcp_flags="S"),
            packet(second=3, dst_ip="192.168.1.20", dst_port=22, length=300, tcp_flags="S"),
            packet(second=4, dst_ip="192.168.1.20", dst_port=53, protocol="DNS", dns_query="example.test"),
            packet(second=5, dst_ip="192.168.1.21", dst_port=80, length=500),
        ]
    )

    by_dst = {feature.dst_ip: feature for feature in features}
    feature = by_dst["192.168.1.20"]

    assert feature.packet_count == 4
    assert feature.byte_count == 700
    assert feature.unique_dst_ports == 4
    assert feature.unique_dst_ips == 1
    assert feature.syn_count == 2
    assert feature.dns_query_count == 1
    assert feature.sensitive_port_count == 1
    assert feature.http_indicator_count == 1
    assert by_dst["192.168.1.21"].packet_count == 1


def test_flow_feature_extractor_streaming_observe_updates_current_window():
    extractor = FlowFeatureExtractor(time_window=60)
    first = extractor.observe(packet(second=1, dst_port=80))
    second = extractor.observe(packet(second=2, dst_port=443, length=250))

    assert first.packet_count == 1
    assert second.packet_count == 2
    assert second.byte_count == 350
    assert second.unique_dst_ports == 2
