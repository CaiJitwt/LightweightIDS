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
    assert record.protocol == "HTTPS"
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


def test_packet_parser_identifies_tls_handshake_payload():
    payload = b"\x16\x03\x01\x00\x2f"
    packet = scapy.IP(src="10.0.0.10", dst="8.8.8.8") / scapy.TCP(sport=52000, dport=443) / scapy.Raw(payload)

    record = PacketParser().parse(packet)

    assert record.protocol == "TLS"


def test_packet_parser_identifies_tls_application_data_on_nonstandard_port():
    payload = b"\x17\x03\x03\x00\x10encrypted-content"
    packet = scapy.IP(src="10.0.0.10", dst="8.8.8.8") / scapy.TCP(sport=52000, dport=3000) / scapy.Raw(payload)

    record = PacketParser().parse(packet)

    assert record.protocol == "TLS"
    assert record.http_method is None


def test_packet_parser_identifies_arp():
    packet = scapy.ARP(psrc="192.168.1.10", pdst="192.168.1.1")

    record = PacketParser().parse(packet)

    assert record.protocol == "ARP"
    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.1"


def test_packet_parser_identifies_common_udp_protocols():
    packet = scapy.IP(src="10.0.0.10", dst="224.0.0.252") / scapy.UDP(sport=5355, dport=5355)

    record = PacketParser().parse(packet)

    assert record.protocol == "LLMNR"


def test_packet_parser_decodes_raw_ethernet_frame_from_capture_startup():
    ethernet_frame = (
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP(src="192.168.1.10", dst="192.168.1.20")
        / scapy.TCP(sport=53000, dport=443, flags="S")
    )
    packet = scapy.Raw(bytes(ethernet_frame))

    record = PacketParser().parse(packet)

    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.20"
    assert record.src_port == 53000
    assert record.dst_port == 443
    assert record.protocol == "HTTPS"
