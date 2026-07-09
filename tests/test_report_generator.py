from __future__ import annotations

import json

from models import AlertRecord, PacketRecord
from report.report_generator import ReportGenerator


def test_report_generator_exports_html_csv_and_json(tmp_path):
    alert = AlertRecord(
        timestamp="2026-01-01 00:00:00.000",
        rule_id="SENSITIVE_PORT",
        rule_name="Sensitive port access",
        alert_type="SENSITIVE_PORT_ACCESS",
        severity="MEDIUM",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        description="Detected access to a sensitive port",
        evidence="dst_port=22",
    )
    packet = PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=22,
        protocol="TCP",
        length=60,
        raw_summary="TCP packet",
    )
    generator = ReportGenerator()

    html_path = tmp_path / "report.html"
    csv_path = tmp_path / "alerts.csv"
    json_path = tmp_path / "alerts.json"

    generator.generate_html_report(
        [alert],
        [packet],
        {
            "severity_distribution": {"MEDIUM": 1},
            "alert_type_distribution": {"SENSITIVE_PORT_ACCESS": 1},
            "top_src_ips": [("10.0.0.1", 1)],
            "top_dst_ports": [(22, 1)],
            "high_or_critical_alerts": 0,
        },
        html_path,
    )
    generator.export_alerts_csv([alert], csv_path)
    generator.export_alerts_json([alert], json_path)

    assert "Lightweight IDS Detection Report" in html_path.read_text(encoding="utf-8")
    assert "SENSITIVE_PORT_ACCESS" in csv_path.read_text(encoding="utf-8-sig")
    assert json.loads(json_path.read_text(encoding="utf-8"))[0]["rule_id"] == "SENSITIVE_PORT"
