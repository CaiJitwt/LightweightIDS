from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from capture.packet_filter import PacketFilter, PacketFilterError
from models import PacketRecord
from ui.widgets.packet_table import PacketTable


def packet(**changes: object) -> PacketRecord:
    values = {
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 53000,
        "dst_port": 443,
        "protocol": "TLS",
        "length": 512,
        "tcp_flags": "SA",
        "raw_summary": "TLS application data",
    }
    values.update(changes)
    return PacketRecord(**values)


def test_wireshark_style_filter_matches_packet_and_builds_capture_bpf():
    compiled = PacketFilter.compile("tcp.port == 443 and ip.addr == 10.0.0.0/8")

    assert compiled.matches(packet()) is True
    assert compiled.matches(packet(dst_port=80)) is False
    assert "tcp" in compiled.capture_filter
    assert "net 10.0.0.0/8" in compiled.capture_filter


def test_bpf_style_filter_supports_implicit_and_direction_qualifiers():
    compiled = PacketFilter.compile("tcp src host 10.0.0.10 and dst portrange 400-500")

    assert compiled.matches(packet(dst_port=443)) is True
    assert compiled.matches(packet(src_ip="10.0.0.11")) is False


def test_application_fields_support_contains_filters():
    compiled = PacketFilter.compile('dns.qry.name contains "example.test"')

    assert compiled.matches(packet(protocol="DNS", dns_query="api.example.test", tcp_flags=None)) is True
    assert compiled.matches(packet(protocol="DNS", dns_query="other.test", tcp_flags=None)) is False
    assert "port 53" in compiled.capture_filter


def test_tcp_flag_and_packet_length_filters():
    compiled = PacketFilter.compile("tcp.flags.syn == 1 and frame.len >= 500")

    assert compiled.matches(packet()) is True
    assert compiled.matches(packet(tcp_flags="A")) is False
    assert compiled.matches(packet(length=100)) is False


def test_invalid_filter_reports_a_clear_error():
    with pytest.raises(PacketFilterError, match="Unsupported"):
        PacketFilter.compile("made.up.field == 1")


def test_packet_table_rebuilds_rows_when_filter_changes():
    app = QApplication.instance() or QApplication([])
    table = PacketTable()
    table.add_packets([packet(), packet(protocol="UDP", src_port=53, dst_port=53000, tcp_flags=None)])

    assert table.rowCount() == 2

    compiled = PacketFilter.compile("tcp")
    table.set_packet_filter(compiled.matches)

    assert table.rowCount() == 1
    assert table.item(0, 3).text() == "TLS"

    table.set_packet_filter(None)

    assert table.rowCount() == 2
    app.processEvents()
