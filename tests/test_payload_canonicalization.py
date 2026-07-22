from __future__ import annotations

import base64

from detection.engine import DetectionEngine
from detection.rules.malicious_command import MaliciousCommandRule
from detection.rules.payload_utils import canonical_text_variants
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.xss import XssRule
from models import PacketRecord


def packet(payload: str) -> PacketRecord:
    return PacketRecord(
        timestamp="2026-07-12 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="HTTP",
        raw_summary=f"HTTP request payload={payload}",
    )


def test_canonicalization_is_bounded_and_decodes_nested_url_and_html_entities():
    variants = canonical_text_variants("%2527%2520OR%25201%253D1 &lt;script&gt;alert(1)&lt;/script&gt;")
    assert len(variants) <= 12
    assert any("' or 1=1" in value for value in variants)
    assert any("<script>alert(1)</script>" in value for value in variants)


def test_rules_detect_canonicalized_sql_xss_and_base64_command_payloads():
    assert SqlInjectionRule().process(packet("%2527%2520OR%25201%253D1"))
    assert XssRule().process(packet("%26lt%3Bsvg%20onload%3Dalert(1)%26gt%3B"))
    encoded_command = base64.b64encode(b"whoami && id").decode("ascii")
    assert MaliciousCommandRule().process(packet(encoded_command))


def test_common_benign_apostrophe_does_not_trigger_sql_injection():
    assert SqlInjectionRule().process(packet("name=O%27Brien")) == []


def test_tcp_rule_index_detects_requests_but_ignores_http_responses():
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=0)
    request = PacketRecord(
        timestamp="2026-07-12 00:00:01.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50_000,
        dst_port=9_000,
        protocol="TCP",
        raw_summary="TCP | payload=POST /search HTTP/1.1 q=<script>alert(1)</script>",
    )
    response = PacketRecord(
        timestamp="2026-07-12 00:00:02.000",
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=9_000,
        dst_port=50_000,
        protocol="TCP",
        raw_summary="TCP | payload=HTTP/1.1 200 OK <script>renderPage()</script>",
    )

    assert "XSS" in {alert.rule_id for alert in engine.process_packet(request)}
    assert "XSS" not in {alert.rule_id for alert in engine.process_packet(response)}
