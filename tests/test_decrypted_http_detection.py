from __future__ import annotations

from capture.decrypted_http_loader import DecryptedHttpLoader
from detection.engine import DetectionEngine
from models import RuleRecord
from parser.decrypted_http_parser import DecryptedHttpParser


def test_decrypted_http_log_reuses_application_detection_rules(tmp_path):
    log_path = tmp_path / "decrypted.jsonl"
    log_path.write_text(
        "\n".join(
            [
                (
                    '{"timestamp":"2026-01-01 00:00:00.000","src_ip":"192.168.1.10",'
                    '"dst_ip":"192.168.1.20","src_port":51000,"dst_port":443,"method":"GET",'
                    '"host":"example.test","path":"/search?q=1 UNION SELECT password FROM users",'
                    '"headers":{"User-Agent":"course-lab"},"body_preview":"","source":"authorized lab proxy"}'
                ),
                (
                    '{"timestamp":"2026-01-01 00:00:11.000","src_ip":"192.168.1.11",'
                    '"dst_ip":"192.168.1.20","src_port":51001,"dst_port":443,"method":"POST",'
                    '"host":"example.test","path":"/comment",'
                    '"headers":{"Content-Type":"application/x-www-form-urlencoded"},'
                    '"body_preview":"message=<script>alert(1)</script>","source":"authorized lab proxy"}'
                ),
                (
                    '{"timestamp":"2026-01-01 00:00:22.000","src_ip":"192.168.1.12",'
                    '"dst_ip":"192.168.1.20","src_port":51002,"dst_port":443,"method":"GET",'
                    '"host":"example.test","path":"/download?file=../../etc/passwd",'
                    '"headers":{},"body_preview":"","source":"authorized lab proxy"}'
                ),
                (
                    '{"timestamp":"2026-01-01 00:00:33.000","src_ip":"192.168.1.13",'
                    '"dst_ip":"192.168.1.20","src_port":51003,"dst_port":443,"method":"POST",'
                    '"host":"example.test","path":"/admin/run","headers":{},'
                    '"body_preview":"cmd=whoami","source":"authorized lab proxy"}'
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parser = DecryptedHttpParser()
    engine = DetectionEngine.from_rule_records(
        [
            RuleRecord("SQL_INJECTION", "SQL injection detection", "web", "CRITICAL", True, 1, 0, ""),
            RuleRecord("XSS", "XSS detection", "web", "HIGH", True, 1, 0, ""),
            RuleRecord("HTTP_SUSPICIOUS", "Suspicious HTTP request", "web", "HIGH", True, 1, 0, ""),
            RuleRecord("MALICIOUS_COMMAND", "Malicious command detection", "web", "CRITICAL", True, 1, 0, ""),
        ],
        alert_cooldown_seconds=0,
    )

    packets = [parser.parse(record) for record in DecryptedHttpLoader().load(log_path)]
    alerts = engine.process_packets(packets)
    alert_types = {alert.alert_type for alert in alerts}

    assert len(packets) == 4
    assert packets[0].protocol == "HTTP"
    assert packets[0].http_host == "example.test"
    assert {"SQL_INJECTION", "XSS", "HTTP_SUSPICIOUS", "MALICIOUS_COMMAND"} <= alert_types
