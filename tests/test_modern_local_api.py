from __future__ import annotations

import json
from threading import Thread
from time import monotonic, sleep
from urllib.request import Request, urlopen

import pytest

from detection.engine import DetectionEngine
from modern_ui.capture_session import CaptureStartOptions, parse_capture_options
from modern_ui.local_api import LocalApiServer
from models import AlertRecord, PacketRecord
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository, RuleRepository


scapy = pytest.importorskip("scapy.all")


def test_capture_request_rejects_invalid_filter():
    defaults = CaptureStartOptions()
    try:
        parse_capture_options({"filterExpression": "unknown.field == value"}, defaults)
    except ValueError as exc:
        assert "Unsupported" in str(exc)
    else:
        raise AssertionError("Invalid capture filter must be rejected")


def test_local_api_serves_status_and_filter_validation(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        with urlopen(f"{base}/api/capture/status", timeout=3) as response:
            assert json.loads(response.read())["state"] == "stopped"
        request = Request(
            f"{base}/api/capture/validate-filter",
            data=json.dumps({"filterExpression": "dns"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read())
        assert "port 53" in payload["bpf"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_serves_persisted_dashboard_alerts_and_host_profile(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    packets = PacketRepository(database)
    alerts = AlertRepository(database)
    packets.add_many(
        [
            PacketRecord(
                timestamp="2026-07-13 12:00:00.100",
                src_ip="10.0.0.42",
                dst_ip="10.0.0.10",
                src_port=51000,
                dst_port=22,
                protocol="TCP",
                length=60,
                tcp_flags="S",
                raw_summary="SSH connection attempt",
            ),
            PacketRecord(
                timestamp="2026-07-13 12:00:01.100",
                src_ip="10.0.0.42",
                dst_ip="10.0.0.11",
                src_port=51001,
                dst_port=22,
                protocol="TCP",
                length=60,
                tcp_flags="S",
                raw_summary="SSH connection attempt",
            ),
        ]
    )
    alert_id = alerts.add(
        AlertRecord(
            timestamp="2026-07-13 12:00:01.100",
            rule_id="HOST_SCAN",
            rule_name="Host scan",
            alert_type="RECONNAISSANCE",
            severity="HIGH",
            src_ip="10.0.0.42",
            dst_ip="10.0.0.11",
            src_port=51001,
            dst_port=22,
            protocol="TCP",
            description="Repeated connection attempts to multiple hosts.",
            evidence="unique_targets=2",
        )
    )

    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        with urlopen(f"{base}/api/dashboard", timeout=3) as response:
            dashboard = json.loads(response.read())
        assert dashboard["statistics"]["packetTotal"] == 2
        assert dashboard["statistics"]["alertTotal"] == 1
        assert dashboard["recentAlerts"][0]["source"] == "10.0.0.42:51001"

        with urlopen(f"{base}/api/alerts", timeout=3) as response:
            alert_payload = json.loads(response.read())
        assert alert_payload["records"][0]["id"] == alert_id

        with urlopen(f"{base}/api/alerts/{alert_id}/packets", timeout=3) as response:
            packet_payload = json.loads(response.read())
        assert len(packet_payload["records"]) == 2
        assert packet_payload["records"][0]["details"]["destinationPort"] == 22

        status_request = Request(
            f"{base}/api/alerts/{alert_id}/status",
            data=json.dumps({"status": "confirmed"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(status_request, timeout=3) as response:
            status_payload = json.loads(response.read())
        assert status_payload["record"]["status"] == "confirmed"

        with urlopen(f"{base}/api/hosts/10.0.0.42", timeout=3) as response:
            host_payload = json.loads(response.read())
        assert host_payload["host"]["packets"] == 2
        assert host_payload["connections"][0]["direction"] == "Outbound"
        assert host_payload["timeline"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_updates_rules_and_resets_statistics(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    packets = PacketRepository(database)
    alerts = AlertRepository(database)
    rules = RuleRepository(database)
    packets.add(PacketRecord(timestamp="2026-07-14 01:00:00.000", src_ip="10.0.0.2", dst_ip="10.0.0.3", protocol="TCP", length=60))
    alerts.add(AlertRecord(timestamp="2026-07-14 01:00:00.000", rule_id="HOST_SCAN", rule_name="Host scan", alert_type="RECONNAISSANCE", severity="HIGH"))

    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        with urlopen(f"{base}/api/rules", timeout=3) as response:
            rule_payload = json.loads(response.read())
        first = rule_payload["records"][0]
        update_request = Request(
            f"{base}/api/rules/{first['id']}",
            data=json.dumps({"enabled": False, "threshold": 17, "timeWindow": 45}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(update_request, timeout=3) as response:
            updated = json.loads(response.read())["record"]
        assert updated["enabled"] is False
        assert updated["threshold"] == 17
        assert updated["timeWindow"] == 45
        persisted = next(rule for rule in rules.list_all() if rule.id == first["id"])
        assert persisted.threshold == 17
        assert persisted.time_window == 45
        runtime_rule = DetectionEngine.from_rule_records(rules.list_all()).get_rule(first["id"])
        assert runtime_rule.threshold == 17
        assert runtime_rule.time_window == 45

        reset_request = Request(f"{base}/api/statistics/reset", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reset_request, timeout=3) as response:
            reset_payload = json.loads(response.read())
        assert reset_payload["reset"] is True
        assert reset_payload["dashboard"]["statistics"]["packetTotal"] == 0
        assert reset_payload["dashboard"]["statistics"]["alertTotal"] == 0
        assert packets.count() == 0
        assert alerts.count() == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_imports_a_uploaded_pcap_in_the_background(tmp_path):
    source_pcap = tmp_path / "import-me.pcap"
    scapy.wrpcap(
        str(source_pcap),
        [scapy.IP(src="192.0.2.10", dst="192.0.2.20") / scapy.TCP(sport=45000, dport=443, flags="S")],
    )
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        request = Request(
            f"{base}/api/pcap/import",
            data=source_pcap.read_bytes(),
            headers={"Content-Type": "application/vnd.tcpdump.pcap", "X-Filename": source_pcap.name},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            assert json.loads(response.read())["state"] == "importing"

        deadline = monotonic() + 5
        status: dict[str, object] = {}
        while monotonic() < deadline:
            with urlopen(f"{base}/api/pcap/status", timeout=3) as response:
                status = json.loads(response.read())
            if status["state"] in {"completed", "error"}:
                break
            sleep(0.05)

        assert status["state"] == "completed", status.get("error")
        assert status["savedPacketTotal"] == 1
        assert PacketRepository(database).count() == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
