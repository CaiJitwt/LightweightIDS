from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from models import AlertRecord, PacketRecord


class ReportGenerator:
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
        top_src_rows = self._tuple_rows(statistics.get("top_src_ips", []), "源 IP", "数量")
        top_port_rows = self._tuple_rows(statistics.get("top_dst_ports", []), "目标端口", "数量")
        alert_rows = "\n".join(self._alert_row(alert) for alert in alerts) or "<tr><td colspan='8'>暂无告警</td></tr>"

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Lightweight IDS 检测报告</title>
  <style>
    body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ margin-bottom: 12px; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #d9e2ec; border-radius: 8px; padding: 14px; background: #f8fafc; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 6px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    .note {{ color: #52616f; }}
  </style>
</head>
<body>
  <h1>Lightweight IDS 检测报告</h1>
  <p class="note">生成时间：{escape(generated_at)}</p>
  <div class="summary">
    <div class="card">数据包总数<div class="value">{len(packets)}</div></div>
    <div class="card">告警总数<div class="value">{len(alerts)}</div></div>
    <div class="card">高危及以上<div class="value">{statistics.get("high_or_critical_alerts", 0)}</div></div>
  </div>

  <h2>告警等级分布</h2>
  {severity_rows}

  <h2>告警类型分布</h2>
  {type_rows}

  <h2>Top 源 IP</h2>
  {top_src_rows}

  <h2>Top 目标端口</h2>
  {top_port_rows}

  <h2>详细告警列表</h2>
  <table>
    <thead>
      <tr><th>时间</th><th>等级</th><th>类型</th><th>规则</th><th>源 IP</th><th>目标 IP</th><th>描述</th><th>状态</th></tr>
    </thead>
    <tbody>
      {alert_rows}
    </tbody>
  </table>

  <h2>安全建议</h2>
  <ul>
    <li>优先复核 HIGH 和 CRITICAL 告警，确认是否为授权实验流量。</li>
    <li>对命中敏感端口的流量检查访问来源、服务暴露范围和访问日志。</li>
    <li>对黑名单 IP 命中项进行隔离分析，避免直接对公网目标做反向测试。</li>
  </ul>
</body>
</html>
"""

    def _dict_rows(self, data: dict[str, int]) -> str:
        if not data:
            return "<p class='note'>暂无数据</p>"
        rows = "".join(f"<tr><td>{escape(str(key))}</td><td>{value}</td></tr>" for key, value in data.items())
        return f"<table><thead><tr><th>项目</th><th>数量</th></tr></thead><tbody>{rows}</tbody></table>"

    def _tuple_rows(self, data: list[tuple[Any, int]], first_title: str, second_title: str) -> str:
        if not data:
            return "<p class='note'>暂无数据</p>"
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
