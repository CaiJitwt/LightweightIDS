from __future__ import annotations

import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import demo_http
from demo_http_lab.main import LOOPBACK_HOST, advertised_addresses, main as lab_main
from demo_http_lab.packet_emitter import PacketEmissionResult, build_custom_demo_packet, build_demo_packet, demo_source_ip
from demo_http_lab.scenarios import SCENARIOS
from demo_http_lab.server import DemoHttpServer, STATIC_ROOT
from detection.engine import DetectionEngine
from parser.packet_parser import PacketParser


pytest.importorskip("scapy.all")
from scapy.all import IP, TCP, Raw  # noqa: E402


WEB_DEMO_RULE_IDS = {
    "HTTP_SUSPICIOUS",
    "MALICIOUS_COMMAND",
    "SQL_INJECTION",
    "WEB_ATTACK",
    "XSS",
}


def test_demo_scenarios_follow_the_real_parser_and_detection_path():
    parser = PacketParser()
    source_ips = set()

    for scenario in SCENARIOS:
        packet = parser.parse(build_demo_packet(scenario))
        alerts = DetectionEngine.with_default_rules(alert_cooldown_seconds=0).process_packet(packet)
        rule_ids = {alert.rule_id for alert in alerts}

        assert packet.protocol == "HTTP"
        assert packet.src_ip == demo_source_ip(scenario)
        source_ips.add(packet.src_ip)
        assert scenario.expected_rule_ids <= rule_ids
        if scenario.id == "benign":
            assert not WEB_DEMO_RULE_IDS.intersection(rule_ids)

    assert len(source_ips) == len(SCENARIOS)


@pytest.mark.parametrize(
    ("body", "expected_rule_ids"),
    [
        (b"text=1%27+UNION+SELECT+username%2Cpassword+FROM+demo_users--", {"SQL_INJECTION"}),
        (b"text=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E", {"XSS"}),
        (b"text=powershell+-enc+DEMO_ONLY_NOT_EXECUTABLE", {"MALICIOUS_COMMAND", "WEB_ATTACK"}),
        (b"text=..%2F..%2F..%2Fetc%2Fpasswd", {"HTTP_SUSPICIOUS", "WEB_ATTACK"}),
        (b"text=%7B%7B7%2A7%7D%7D", {"WEB_ATTACK"}),
        (
            b"text=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
            {"HTTP_SUSPICIOUS", "WEB_ATTACK"},
        ),
    ],
)
def test_custom_text_runs_all_applicable_http_detection_rules(body, expected_rule_ids):
    packet = PacketParser().parse(build_custom_demo_packet(body))
    alerts = DetectionEngine.with_default_rules(alert_cooldown_seconds=0).process_packet(packet)

    assert packet.protocol == "HTTP"
    assert expected_rule_ids <= {alert.rule_id for alert in alerts}


def test_one_custom_packet_can_trigger_every_matching_http_rule():
    body = (
        b"text=1%27+UNION+SELECT+username%2Cpassword+FROM+demo_users--"
        b"&comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E"
        b"&command=powershell+-enc+DEMO_ONLY_NOT_EXECUTABLE"
        b"&file=..%2F..%2F..%2Fetc%2Fpasswd"
    )
    packet = PacketParser().parse(build_custom_demo_packet(body))
    alerts = DetectionEngine.with_default_rules(alert_cooldown_seconds=0).process_packet(packet)

    assert {
        "HTTP_SUSPICIOUS",
        "MALICIOUS_COMMAND",
        "SQL_INJECTION",
        "WEB_ATTACK",
        "XSS",
    } <= {alert.rule_id for alert in alerts}


def test_custom_packets_use_distinct_sources_to_avoid_cross_request_cooldown():
    first = PacketParser().parse(build_custom_demo_packet(b"text=first", sequence=0))
    second = PacketParser().parse(build_custom_demo_packet(b"text=second", sequence=1))

    assert first.src_ip != second.src_ip


def test_loading_the_demo_page_does_not_trigger_its_attack_scenarios():
    parser = PacketParser()
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)

    for index, filename in enumerate(("index.html", "app.js", "styles.css")):
        content = (STATIC_ROOT / filename).read_bytes()
        response = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + content
        packet = parser.parse(
            IP(src=LOOPBACK_HOST, dst=LOOPBACK_HOST)
            / TCP(sport=8080, dport=52_000 + index, flags="PA")
            / Raw(load=response)
        )
        rule_ids = {alert.rule_id for alert in engine.process_packet(packet)}

        assert not WEB_DEMO_RULE_IDS.intersection(rule_ids), filename


def test_simple_entry_opens_browser_and_defaults_to_ipv4_loopback(monkeypatch):
    received = []

    def fake_lab_main(arguments):
        received.append(arguments)
        return 0

    monkeypatch.setattr(demo_http, "lab_main", fake_lab_main)

    assert demo_http.main(["--receiver-only"]) == 0
    assert received == [["--open-browser", "--receiver-only"]]
    assert advertised_addresses(LOOPBACK_HOST) == [LOOPBACK_HOST]
    assert advertised_addresses("localhost") == [LOOPBACK_HOST]
    assert advertised_addresses("0.0.0.0", "192.168.56.1") == ["192.168.56.1"]


def test_demo_server_classroom_mode_discards_request_content_without_a_token():
    emitted = []

    def emit(scenario_id: str, body: bytes) -> PacketEmissionResult:
        emitted.append(scenario_id)
        return PacketEmissionResult("WLAN", "Test adapter", "192.0.2.10", "192.0.2.200", 8080)

    server = DemoHttpServer(("127.0.0.1", 0), packet_emitter=emit)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(f"{base_url}/", timeout=3) as response:
            assert response.status == 200
            assert b"Lightweight IDS HTTP Alert Lab" in response.read()

        submitted = b"message=private-content"
        request = Request(
            f"{base_url}/sink/benign",
            data=submitted,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            body = response.read()
            result = json.loads(body)

        assert response.status == 202
        assert result["accepted"] is True
        assert result["emitted"] is True
        assert result["interface"] == "WLAN"
        assert result["receivedBytes"] == len(submitted)
        assert submitted not in body
        assert emitted == ["benign"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_custom_text_is_injected_for_normal_detection():
    emitted = []

    def emit(scenario_id: str, body: bytes) -> PacketEmissionResult:
        emitted.append(scenario_id)
        return PacketEmissionResult("WLAN", "Test adapter", "192.0.2.10", "192.0.2.200", 8080)

    server = DemoHttpServer(("127.0.0.1", 0), packet_emitter=emit)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = Request(f"{base_url}/sink/custom", data=b"text=custom", method="POST")
        with urlopen(request, timeout=3) as response:
            result = json.loads(response.read())

        assert response.status == 202
        assert result["emitted"] is True
        assert emitted == ["custom"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_server_can_optionally_require_a_token():
    server = DemoHttpServer(("127.0.0.1", 0), token="test-token")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        unauthorized = Request(f"{base_url}/sink/benign", data=b"message=test", method="POST")
        with pytest.raises(HTTPError) as error:
            urlopen(unauthorized, timeout=3)
        assert error.value.code == 403

        authorized = Request(
            f"{base_url}/sink/benign",
            data=b"message=test",
            headers={"X-Demo-Token": "test-token"},
            method="POST",
        )
        with urlopen(authorized, timeout=3) as response:
            assert response.status == 202
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_server_restricts_clients_body_size_and_rate():
    server = DemoHttpServer(
        ("127.0.0.1", 0),
        token="test-token",
        max_body_bytes=8,
        requests_per_minute=1,
    )
    assert server.client_is_allowed("127.0.0.1") is True
    assert server.client_is_allowed("192.168.56.20") is True
    assert server.client_is_allowed("8.8.8.8") is False
    assert server.accept_rate_limit("192.168.56.20") is True
    assert server.accept_rate_limit("192.168.56.20") is False
    server.server_close()
