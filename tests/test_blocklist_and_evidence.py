from __future__ import annotations

from datetime import datetime, timedelta

from detection.engine import DetectionEngine
from models import AlertRecord, BlocklistEntry, PacketRecord, RuleRecord
from protection.blocklist_service import BlocklistService, WindowsFirewallEnforcer
from storage.blocklist_repository import BlocklistEntryRepository
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository


def test_blocklist_service_persists_and_builds_windows_firewall_rules(tmp_path, monkeypatch):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    commands: list[list[str]] = []

    def runner(arguments: list[str]) -> tuple[int, str]:
        commands.append(arguments)
        return 0, "Ok."

    monkeypatch.setattr("protection.blocklist_service.sys.platform", "win32")
    service = BlocklistService(database, WindowsFirewallEnforcer(runner))
    entry, result = service.add_and_enforce(kind="IP", value="203.0.113.10", field="SRC_IP")

    assert result.success is True
    assert entry.enforcement_status == "Active"
    assert BlocklistEntryRepository(database).get(entry.id).enforcement_status == "Active"  # type: ignore[arg-type,union-attr]
    add_commands = [command for command in commands if command[3] == "add"]
    assert len(add_commands) == 2
    assert any("remoteip=203.0.113.10" in command for command in add_commands)
    assert any("localip=203.0.113.10" in command for command in add_commands)
    assert any("dir=in" in command for command in add_commands)
    assert any("dir=out" in command for command in add_commands)


def test_port_blocklist_matches_packets_and_is_used_by_detection_engine(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    entry = BlocklistEntry(kind="PORT", value="4444", field="DST_PORT", protocol="TCP")
    packet = PacketRecord(
        timestamp="2026-07-12 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=4444,
        protocol="TCP",
        length=60,
    )
    record = RuleRecord(
        id="BLACKLIST_IP",
        name="Blacklisted IP match",
        category="reputation",
        severity="HIGH",
        enabled=True,
        threshold=1,
        time_window=0,
        description="Blocked network value",
    )

    alerts = DetectionEngine.from_rule_records(
        [record],
        alert_cooldown_seconds=0,
        blocklist_entries=[entry],
    ).process_packet(packet)
    assert len(alerts) == 1
    assert "DST_PORT=4444" in alerts[0].evidence


def test_related_packet_query_returns_window_packets_for_host_scan(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    packets = PacketRepository(database)
    base = datetime(2026, 7, 12, 0, 0, 0)
    packets.add_many(
        [
            PacketRecord(
                timestamp=(base + timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                src_ip="10.0.0.1",
                dst_ip=f"10.0.1.{index + 1}",
                src_port=50000 + index,
                dst_port=80,
                protocol="TCP",
                length=60,
            )
            for index in range(4)
        ]
    )
    alert = AlertRecord(
        timestamp=(base + timedelta(seconds=3)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        rule_id="HOST_SCAN",
        rule_name="Host scan",
        alert_type="HOST_SCAN",
        severity="HIGH",
        src_ip="10.0.0.1",
        dst_ip="10.0.1.4",
        src_port=50003,
        dst_port=80,
        protocol="TCP",
    )

    related = packets.list_related_to_alert(alert)
    assert len(related) == 4
    assert {packet.dst_ip for packet in related} == {"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"}
