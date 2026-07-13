from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from models import AlertRecord, InvestigationEvidenceRecord, InvestigationRecord, PacketRecord


class ReportGenerator:
    def generate_investigation_html(
        self,
        investigation: InvestigationRecord,
        evidence: list[InvestigationEvidenceRecord],
        output_path: str | Path,
    ) -> None:
        rows = "".join(
            "<tr>"
            f"<td>{escape(item.alert_timestamp)}</td>"
            f"<td>{escape(item.severity)}</td>"
            f"<td>{escape(item.rule_name)}</td>"
            f"<td>{escape(item.src_ip or '')}</td>"
            f"<td>{escape(item.dst_ip or '')}</td>"
            f"<td>{escape(item.description)}</td>"
            f"<td>{escape(item.evidence)}</td>"
            "</tr>"
            for item in evidence
        ) or "<tr><td colspan='7'>No evidence</td></tr>"
        html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{escape(investigation.title)}</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#1f2933}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d9e2ec;padding:8px;text-align:left;vertical-align:top}}th{{background:#eef2f7}}</style>
</head><body><h1>{escape(investigation.title)}</h1>
<p><strong>Status:</strong> {escape(investigation.status)} &nbsp; <strong>Priority:</strong> {escape(investigation.priority)} &nbsp; <strong>Host:</strong> {escape(investigation.host_ip or '')}</p>
<h2>Summary</h2><p>{escape(investigation.summary)}</p><h2>Notes</h2><p>{escape(investigation.notes)}</p>
<h2>Evidence</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Description</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

    def generate_html_report(
        self,
        alerts: list[AlertRecord],
        packets: list[PacketRecord],
        statistics: dict[str, Any],
        output_path: str | Path,
    ) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._build_html(alerts, packets, statistics), encoding="utf-8")

    def export_alerts_csv(self, alerts: list[AlertRecord], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "id",
            "timestamp",
            "rule_id",
            "rule_name",
            "alert_type",
            "severity",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "description",
            "evidence",
            "status",
        ]
        with path.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                writer.writerow({key: asdict(alert).get(key) for key in fieldnames})

    def export_alerts_json(self, alerts: list[AlertRecord], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(alert) for alert in alerts]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _build_html(self, alerts: list[AlertRecord], packets: list[PacketRecord], statistics: dict[str, Any]) -> str:
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_rows = self._dict_rows(statistics.get("severity_distribution", {}))
        type_rows = self._dict_rows(statistics.get("alert_type_distribution", {}))
        top_src_rows = self._tuple_rows(statistics.get("top_src_ips", []), "Source IP", "Count")
        top_port_rows = self._tuple_rows(statistics.get("top_dst_ports", []), "Destination port", "Count")
        alert_rows = "\n".join(self._alert_row(alert) for alert in alerts) or "<tr><td colspan='8'>No alerts</td></tr>"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Lightweight IDS Detection Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ margin-bottom: 12px; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #d9e2ec; border-radius: 8px; padding: 14px; background: #f8fafc; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 6px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; table-layout: auto; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; vertical-align: top; word-break: break-word; }}
    th {{ background: #eef2f7; }}
    .note {{ color: #52616f; }}
  </style>
</head>
<body>
  <h1>Lightweight IDS Detection Report</h1>
  <p class="note">Generated at: {escape(generated_at)}</p>
  <div class="summary">
    <div class="card">Total packets<div class="value">{len(packets)}</div></div>
    <div class="card">Total alerts<div class="value">{len(alerts)}</div></div>
    <div class="card">High or critical alerts<div class="value">{statistics.get("high_or_critical_alerts", 0)}</div></div>
  </div>

  <h2>Alert Severity Distribution</h2>
  {severity_rows}

  <h2>Alert Type Distribution</h2>
  {type_rows}

  <h2>Top Source IPs</h2>
  {top_src_rows}

  <h2>Top Destination Ports</h2>
  {top_port_rows}

  <h2>Detailed Alert List</h2>
  <table>
    <thead>
      <tr><th>Time</th><th>Severity</th><th>Type</th><th>Rule</th><th>Source IP</th><th>Destination IP</th><th>Description</th><th>Status</th></tr>
    </thead>
    <tbody>
      {alert_rows}
    </tbody>
  </table>

  <h2>Security Recommendations</h2>
  <ul>
    <li>Review HIGH and CRITICAL alerts first and confirm whether they are authorized lab traffic.</li>
    <li>For sensitive port alerts, check the access source, exposed service scope and service logs.</li>
    <li>For blacklist matches, isolate and analyze the related host before taking any external action.</li>
  </ul>
</body>
</html>
"""

    def _dict_rows(self, data: dict[str, int]) -> str:
        if not data:
            return "<p class='note'>No data</p>"
        rows = "".join(f"<tr><td>{escape(str(key))}</td><td>{value}</td></tr>" for key, value in data.items())
        return f"<table><thead><tr><th>Item</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>"

    def _tuple_rows(self, data: list[tuple[Any, int]], first_title: str, second_title: str) -> str:
        if not data:
            return "<p class='note'>No data</p>"
        rows = "".join(f"<tr><td>{escape(str(key))}</td><td>{value}</td></tr>" for key, value in data)
        return f"<table><thead><tr><th>{escape(first_title)}</th><th>{escape(second_title)}</th></tr></thead><tbody>{rows}</tbody></table>"

    def _alert_row(self, alert: AlertRecord) -> str:
        return (
            "<tr>"
            f"<td>{escape(alert.timestamp)}</td>"
            f"<td>{escape(alert.severity)}</td>"
            f"<td>{escape(alert.alert_type)}</td>"
            f"<td>{escape(alert.rule_name)}</td>"
            f"<td>{escape(alert.src_ip or '')}</td>"
            f"<td>{escape(alert.dst_ip or '')}</td>"
            f"<td>{escape(alert.description)}</td>"
            f"<td>{escape(alert.status)}</td>"
            "</tr>"
        )
