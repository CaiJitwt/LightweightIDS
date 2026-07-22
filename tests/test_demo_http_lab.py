from __future__ import annotations

import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

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

    for index, scenario in enumerate(SCENARIOS):
        request = _http_request(scenario.id, scenario.body)
        packet = parser.parse(
            IP(src="192.168.56.20", dst="192.168.56.1")
            / TCP(sport=51_000 + index, dport=8080, flags="PA")
            / Raw(load=request)
        )
        alerts = DetectionEngine.with_default_rules(alert_cooldown_seconds=0).process_packet(packet)
        rule_ids = {alert.rule_id for alert in alerts}

        assert packet.protocol == "HTTP"
        assert scenario.expected_rule_ids <= rule_ids
        if scenario.id == "benign":
            assert not WEB_DEMO_RULE_IDS.intersection(rule_ids)


def test_loading_the_demo_page_does_not_trigger_its_attack_scenarios():
    parser = PacketParser()
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)

    for index, filename in enumerate(("index.html", "app.js", "styles.css")):
        content = (STATIC_ROOT / filename).read_bytes()
        response = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + content
        packet = parser.parse(
            IP(src="192.168.56.1", dst="192.168.56.20")
            / TCP(sport=8080, dport=52_000 + index, flags="PA")
            / Raw(load=response)
        )
        rule_ids = {alert.rule_id for alert in engine.process_packet(packet)}

        assert not WEB_DEMO_RULE_IDS.intersection(rule_ids), filename


def test_demo_server_classroom_mode_discards_request_content_without_a_token():
    server = DemoHttpServer(("127.0.0.1", 0))
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
        assert result["receivedBytes"] == len(submitted)
        assert submitted not in body
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


def _http_request(scenario_id: str, body: str) -> bytes:
    encoded = body.encode()
    return (
        f"POST /sink/{scenario_id} HTTP/1.1\r\n"
        "Host: 192.168.56.1:8080\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(encoded)}\r\n\r\n"
    ).encode() + encoded
