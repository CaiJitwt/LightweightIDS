from __future__ import annotations

import pytest

from parser.packet_parser import PacketParser

scapy = pytest.importorskip("scapy.all")


def test_packet_parser_extracts_tcp_fields():
    packet = scapy.IP(src="192.168.1.10", dst="192.168.1.20") / scapy.TCP(sport=12345, dport=443, flags="S")

    record = PacketParser().parse(packet)

    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.20"
    assert record.src_port == 12345
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert record.tcp_flags == "S"


def test_packet_parser_extracts_dns_query():
    packet = (
        scapy.IP(src="10.0.0.10", dst="8.8.8.8")
        / scapy.UDP(sport=5353, dport=53)
        / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
    )

    record = PacketParser().parse(packet)

    assert record.protocol == "DNS"
    assert record.dns_query == "example.com"


def test_packet_parser_extracts_http_request_fields():
    payload = b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packet = scapy.IP(src="10.0.0.10", dst="10.0.0.20") / scapy.TCP(sport=52000, dport=80) / scapy.Raw(payload)

    record = PacketParser().parse(packet)

    assert record.protocol == "HTTP"
    assert record.http_method == "GET"
    assert record.http_host == "example.com"
    assert record.http_path == "/login"
