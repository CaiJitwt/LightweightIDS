from __future__ import annotations

from detection.features import FlowFeature
from detection.ml import IsolationForestFlowDetector
from detection.rules.abnormal_outbound import AbnormalOutboundRule
from detection.rules.malicious_command import MaliciousCommandRule
from detection.rules.ml_flow_anomaly import MlFlowAnomalyRule
from detection.rules.session_duration_anomaly import SessionDurationAnomalyRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.web_attack import WebAttackRule
from detection.rules.xss import XssRule
from models import PacketRecord


def packet(
    second: int,
    *,
    protocol: str = "HTTPS",
    src_port: int = 55000,
    dst_port: int = 443,
    length: int = 400,
    raw_summary: str = "TLS application data",
    http_method: str = "",
    http_host: str = "",
    http_path: str = "",
    raw_hex: str = "",
) -> PacketRecord:
    minute, sec = divmod(second, 60)
    return PacketRecord(
        timestamp=f"2026-07-12 22:{minute:02d}:{sec:02d}.000",
        src_ip="198.18.0.1",
        dst_ip="198.18.0.26",
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags="PA",
        raw_summary=raw_summary,
        http_method=http_method,
        http_host=http_host,
        http_path=http_path,
        raw_hex=raw_hex,
    )


def test_opaque_https_bytes_are_not_scanned_as_web_content():
    encrypted = packet(1, raw_summary="TLS payload with random ${normal} <script> UNION SELECT ; whoami")

    rules = [WebAttackRule(), SqlInjectionRule(), XssRule(), MaliciousCommandRule()]

    assert all(rule.process(encrypted) == [] for rule in rules)


def test_plain_http_content_remains_available_to_web_rules():
    plaintext = packet(
        1,
        protocol="HTTP",
        dst_port=80,
        raw_summary="GET /render?name=${7*7} HTTP/1.1 Host: lab.test",
    )

    assert WebAttackRule().process(plaintext)


def test_loopback_host_header_is_not_treated_as_an_ssrf_target():
    normal = packet(
        1,
        protocol="HTTP",
        dst_port=8080,
        raw_summary=(
            "POST /sink/benign HTTP/1.1\r\n"
            "Host: 127.0.0.1:8080\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            "message=demo-health-check&status=ok"
        ),
        http_method="POST",
        http_host="127.0.0.1:8080",
        http_path="/sink/benign",
    )
    ssrf = packet(
        2,
        protocol="HTTP",
        dst_port=8080,
        raw_summary=(
            "POST /sink/ssrf HTTP/1.1\r\n"
            "Host: 127.0.0.1:8080\r\n\r\n"
            "url=http://127.0.0.1/admin"
        ),
        http_method="POST",
        http_host="127.0.0.1:8080",
        http_path="/sink/ssrf",
    )

    assert WebAttackRule().process(normal) == []
    assert WebAttackRule().process(ssrf)


def test_ssrf_after_long_http_prefix_remains_visible_to_advanced_rule():
    body = b"padding=" + b"a" * 400 + b"&url=http://127.0.0.1/admin"
    request = (
        b"POST /sink/custom HTTP/1.1\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    suspicious = packet(
        3,
        protocol="HTTP",
        dst_port=8080,
        raw_summary=request[:240].decode("ascii"),
        raw_hex=request.hex(),
        http_method="POST",
        http_host="127.0.0.1:8080",
        http_path="/sink/custom",
    )

    alerts = WebAttackRule().process(suspicious)

    assert alerts
    assert "ssrf_loopback" in alerts[0].evidence


def test_one_normal_uncommon_port_connection_is_not_reported_per_packet():
    rule = AbnormalOutboundRule(threshold=4, time_window=300)

    alerts = []
    for second in range(20):
        alerts.extend(rule.process(packet(second, protocol="TCP", dst_port=3000, src_port=55575)))

    assert alerts == []


def test_session_duration_rule_ignores_normal_https_sessions():
    rule = SessionDurationAnomalyRule(threshold=2, min_history=1, min_extra_seconds=1)

    assert rule.process(packet(0)) == []
    assert rule.process(packet(120)) == []


def test_ml_flow_rule_does_not_treat_https_volume_alone_as_an_attack(tmp_path):
    detector = IsolationForestFlowDetector(
        model_path=tmp_path / "flow.pkl",
        use_sklearn=False,
        min_train_samples=3,
    )
    detector.train(
        [
            FlowFeature("198.18.0.1", "198.18.0.26", 0, 60, packet_count=5, byte_count=1200),
            FlowFeature("198.18.0.1", "198.18.0.26", 60, 60, packet_count=6, byte_count=1400),
            FlowFeature("198.18.0.1", "198.18.0.26", 120, 60, packet_count=7, byte_count=1500),
        ]
    )
    rule = MlFlowAnomalyRule(detector=detector, threshold=80, time_window=60)

    alerts = []
    for second in range(70):
        alerts.extend(rule.process(packet(180 + second, length=500)))

    assert alerts == []
