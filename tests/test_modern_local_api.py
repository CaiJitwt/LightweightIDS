from __future__ import annotations

import json
from threading import Thread
from time import monotonic, sleep
from urllib.request import Request, urlopen

import pytest

from detection.engine import DetectionEngine
from endpoint_security.event_log import EventCollectionResult
from modern_ui.capture_session import CaptureStartOptions, parse_capture_options
from modern_ui.local_api import LocalApiServer
from models import AlertRecord, PacketRecord, SecurityEventRecord
from storage.analyst_repositories import AssetRepository, InvestigationRepository
from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository, RuleRepository, SecurityEventRepository


scapy = pytest.importorskip("scapy.all")


class StubSecurityEventCollector:
    is_windows = True

    def collect(self, _cursors: dict[str, int], limit_per_channel: int = 200) -> EventCollectionResult:
        return EventCollectionResult(
            records=[
                SecurityEventRecord(
                    timestamp="2026-07-14T01:02:03+00:00",
                    channel="System",
                    event_id=7045,
                    record_id=17,
                    provider="Service Control Manager",
                    computer="LAB-PC",
                    user="SYSTEM",
                    summary="A service was installed in the system.",
                    details={
                        "ServiceName": "RemoteUpdate",
                        "ImagePath": r"powershell.exe -EncodedCommand SQBFAFgA",
                    },
                    severity="HIGH",
                )
            ]
        )


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
        with urlopen(f"{base}/api/health", timeout=3) as response:
            health = json.loads(response.read())
        assert health["apiVersion"] >= 3
        assert isinstance(health["elevated"], bool)
        assert "endpoint-security-v1" in health["capabilities"]
        assert "analyst-workflow-v1" in health["capabilities"]
        assert health["database"] == str(database.path.resolve())

        with urlopen(f"{base}/api/system/health", timeout=3) as response:
            system_health = json.loads(response.read())
        assert system_health["system"]["hostname"]
        assert system_health["system"]["logicalProcessors"] >= 1
        assert system_health["engine"]["rulesLoaded"] > 0
        assert system_health["detectors"]

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
    security_events = SecurityEventRepository(database)
    packets.add_many(
        [
            PacketRecord(timestamp="2026-07-14 01:00:00.000", src_ip="10.0.0.2", dst_ip="10.0.0.3", protocol="TCP", length=60),
            PacketRecord(timestamp="2026-07-14 01:00:01.000", src_ip="10.0.0.2", dst_ip="10.0.0.3", protocol="TCP", length=100),
            PacketRecord(timestamp="2026-07-14 01:00:02.000", src_ip="10.0.0.2", dst_ip="8.8.8.8", protocol="DNS", length=80),
        ]
    )
    alerts.add(AlertRecord(timestamp="2026-07-14 01:00:00.000", rule_id="HOST_SCAN", rule_name="Host scan", alert_type="RECONNAISSANCE", severity="HIGH"))
    security_events.add_many(
        [SecurityEventRecord(timestamp="2026-07-14T01:00:00+00:00", channel="System", event_id=7045, record_id=88)]
    )
    security_events.update_cursor("System", 88)

    server = LocalApiServer(("127.0.0.1", 0), database)
    server.capture_service._packet_total = 9
    server.capture_service._alert_total = 4
    server.capture_service._sequence = 13
    server.capture_service._recent_packets.append({"sequence": 13})
    server.pcap_import._state = "completed"
    server.pcap_import._filename = "previous.pcap"
    server.pcap_import._packet_total = 9
    server.pcap_import._alert_total = 4
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

        with urlopen(f"{base}/api/topology", timeout=3) as response:
            topology = json.loads(response.read())
        assert {node["ip"] for node in topology["nodes"]} == {"10.0.0.2", "10.0.0.3", "8.8.8.8"}
        assert next(node for node in topology["nodes"] if node["ip"] == "8.8.8.8")["kind"] == "external"
        tcp_edge = next(edge for edge in topology["edges"] if edge["protocol"] == "TCP")
        assert tcp_edge["source"] == "10.0.0.2"
        assert tcp_edge["target"] == "10.0.0.3"
        assert tcp_edge["packets"] == 2
        assert tcp_edge["bytes"] == 160

        with urlopen(f"{base}/api/timeline", timeout=3) as response:
            timeline_before_reset = json.loads(response.read())
        assert any(record["kind"] == "packet" for record in timeline_before_reset["records"])
        assert any(record["kind"] == "alert" for record in timeline_before_reset["records"])

        reset_request = Request(f"{base}/api/statistics/reset", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(reset_request, timeout=3) as response:
            reset_payload = json.loads(response.read())
        assert reset_payload["reset"] is True
        assert reset_payload["dashboard"]["statistics"]["packetTotal"] == 0
        assert reset_payload["dashboard"]["statistics"]["alertTotal"] == 0
        assert reset_payload["dashboard"]["capture"]["packetTotal"] == 0
        assert reset_payload["dashboard"]["capture"]["alertTotal"] == 0
        assert packets.count() == 0
        assert alerts.count() == 0
        assert security_events.count() == 0
        assert security_events.cursors()["System"] == 88

        with urlopen(f"{base}/api/topology", timeout=3) as response:
            reset_topology = json.loads(response.read())
        assert reset_topology == {"nodes": [], "edges": []}

        with urlopen(f"{base}/api/timeline", timeout=3) as response:
            reset_timeline = json.loads(response.read())
        assert reset_timeline == {"records": []}

        with urlopen(f"{base}/api/pcap/status", timeout=3) as response:
            pcap_status = json.loads(response.read())
        assert pcap_status["state"] == "idle"
        assert pcap_status["filename"] == ""
        assert pcap_status["packetTotal"] == 0

        first_packet = PacketRecord(
            timestamp="2026-07-14 02:00:00.000",
            src_ip="10.0.0.4",
            dst_ip="10.0.0.5",
            protocol="TCP",
            length=60,
        )
        assert packets.add(first_packet) == 1
        server.capture_service._append_packet(first_packet)
        live_records = server.capture_service.packets_since(0)["records"]
        assert live_records[0]["sequence"] == 1
        assert live_records[0]["id"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_topology_uses_unsaved_live_capture_window(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    server.capture_service._options = CaptureStartOptions(save_packets=False)
    server.capture_service._append_packet(
        PacketRecord(
            timestamp="2026-07-14 03:00:00.000",
            src_ip="192.168.1.10",
            dst_ip="1.1.1.1",
            protocol="DNS",
            length=90,
        )
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with urlopen(f"http://{host}:{port}/api/topology", timeout=3) as response:
            topology = json.loads(response.read())
        assert PacketRepository(database).count() == 0
        assert {node["ip"] for node in topology["nodes"]} == {"192.168.1.10", "1.1.1.1"}
        assert topology["edges"][0]["protocol"] == "DNS"
        assert topology["edges"][0]["packets"] == 1
        assert next(node for node in topology["nodes"] if node["ip"] == "192.168.1.10")["packets"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_refreshes_security_events_and_links_generated_alert(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    server.security_event_monitor.collector = StubSecurityEventCollector()  # type: ignore[assignment]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        refresh_request = Request(
            f"{base}/api/security/events/refresh",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(refresh_request, timeout=3) as response:
            refresh_payload = json.loads(response.read())
        assert refresh_payload["eventsAdded"] == 1
        assert refresh_payload["alertsAdded"] == 1

        with urlopen(f"{base}/api/security/events", timeout=3) as response:
            events_payload = json.loads(response.read())
        assert events_payload["total"] == 1
        security_event = events_payload["records"][0]
        assert security_event["eventId"] == 7045
        assert security_event["alertId"] is not None

        with urlopen(f"{base}/api/alerts/{security_event['alertId']}/security-event", timeout=3) as response:
            linked_payload = json.loads(response.read())
        assert linked_payload["record"]["recordId"] == 17
        assert linked_payload["record"]["details"]["ServiceName"] == "RemoteUpdate"
        assert SecurityEventRepository(database).count() == 1
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

        with urlopen(f"{base}/api/packets?after=0&limit=250", timeout=3) as response:
            activity = json.loads(response.read())
        assert len(activity["records"]) == 1
        assert activity["records"][0]["details"]["src_ip"] == "192.0.2.10"

        with urlopen(f"{base}/api/capture/status", timeout=3) as response:
            capture_status = json.loads(response.read())
        assert capture_status["packetTotal"] == 1
        assert capture_status["savedPacketTotal"] == 1

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_api_persists_asset_and_investigation_crud(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"

    def request_json(path: str, *, method: str = "GET", payload: dict[str, object] | None = None):
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(
            f"{base}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())

    try:
        status, created_asset = request_json(
            "/api/assets",
            method="POST",
            payload={
                "ip": "10.0.0.10",
                "displayName": "Database-01",
                "role": "Database",
                "importance": 85,
                "notes": "Primary course lab database",
            },
        )
        assert status == 201
        assert created_asset["record"]["display_name"] == "Database-01"

        _, asset_list = request_json("/api/assets")
        assert [record["ip"] for record in asset_list["records"]] == ["10.0.0.10"]

        _, updated_asset = request_json(
            "/api/assets/10.0.0.10",
            method="PUT",
            payload={"displayName": "Database-Primary", "role": "Database", "importance": 95, "notes": "Updated"},
        )
        assert updated_asset["record"]["importance"] == 95
        assert AssetRepository(database).get("10.0.0.10").display_name == "Database-Primary"  # type: ignore[union-attr]

        status, created_case = request_json(
            "/api/investigations",
            method="POST",
            payload={
                "title": "Review database activity",
                "status": "Open",
                "priority": "HIGH",
                "hostIp": "10.0.0.10",
                "summary": "Validate recent alerts.",
                "notes": "Created from the modern workspace.",
            },
        )
        assert status == 201
        investigation_id = created_case["record"]["id"]

        _, updated_case = request_json(
            f"/api/investigations/{investigation_id}",
            method="PUT",
            payload={
                "title": "Review database activity",
                "status": "Monitoring",
                "priority": "CRITICAL",
                "hostIp": "10.0.0.10",
                "summary": "Validation is in progress.",
                "notes": "Persisted edit.",
            },
        )
        assert updated_case["record"]["status"] == "Monitoring"

        _, case_detail = request_json(f"/api/investigations/{investigation_id}")
        assert case_detail["record"]["notes"] == "Persisted edit."
        assert case_detail["evidence"] == []
        assert InvestigationRepository(database).get(investigation_id).priority == "CRITICAL"  # type: ignore[union-attr]

        _, deleted_case = request_json(f"/api/investigations/{investigation_id}", method="DELETE")
        _, deleted_asset = request_json("/api/assets/10.0.0.10", method="DELETE")
        assert deleted_case == {"deleted": True}
        assert deleted_asset == {"deleted": True}
        assert InvestigationRepository(database).get(investigation_id) is None
        assert AssetRepository(database).get("10.0.0.10") is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
