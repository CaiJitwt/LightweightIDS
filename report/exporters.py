from __future__ import annotations

from pathlib import Path

from models import AlertRecord
from report.report_generator import ReportGenerator


class CsvExporter:
    def export(self, alerts: list[AlertRecord], output_path: str | Path) -> None:
        ReportGenerator().export_alerts_csv(alerts, output_path)


class JsonExporter:
    def export(self, alerts: list[AlertRecord], output_path: str | Path) -> None:
        ReportGenerator().export_alerts_json(alerts, output_path)
