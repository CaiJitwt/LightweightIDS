from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from detection.analysis.attack_chain import AttackChain, AttackChainAnalyzer
from detection.analysis.alert_trend import AlertTrendAnalyzer, AlertTrendPoint
from detection.analysis.host_risk import HostRiskBreakdown, HostRiskScorer
from detection.baseline import BaselineManager
from detection.ml.simple_anomaly import SimpleAnomalyDetector
from models import AlertRecord, BaselineRecord
from storage.database import Database
from storage.repositories import AlertRepository, BaselineRepository, PacketRepository
from ui.widgets.chart_widget import ChartWidget
from ui.widgets.statistic_card import StatisticCard
from ui.styles import configure_responsive_table


class DashboardPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.baseline_repository = BaselineRepository(database)
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.host_risk_scorer = HostRiskScorer(self.attack_chain_analyzer)
        self.alert_trend_analyzer = AlertTrendAnalyzer()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(16)
        self.scroll_area.setWidget(content)
        outer_layout.addWidget(self.scroll_area)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh statistics")
        toolbar.addWidget(self.refresh_button)
        toolbar.addStretch()

        cards = QGridLayout()
        cards.setSpacing(12)
        self.packet_card = StatisticCard("Processed packets", "0")
        self.alert_card = StatisticCard("Total alerts", "0")
        self.high_card = StatisticCard("High-risk alerts", "0")
        self.status_card = StatisticCard("Detection status", "Waiting")
        cards.addWidget(self.packet_card, 0, 0)
        cards.addWidget(self.alert_card, 0, 1)
        cards.addWidget(self.high_card, 0, 2)
        cards.addWidget(self.status_card, 0, 3)
        for column in range(4):
            cards.setColumnStretch(column, 1)

        charts = QGridLayout()
        charts.setSpacing(12)
        self.protocol_chart = ChartWidget("Protocol distribution")
        self.severity_chart = ChartWidget("Alert severity")
        self.top_src_chart = ChartWidget("Top source IPs")
        self.top_port_chart = ChartWidget("Top destination ports")
        self.attack_chain_chart = ChartWidget("Attack chain stages")
        self.anomaly_score_chart = ChartWidget("Anomaly score trend")
        charts.addWidget(self.protocol_chart, 0, 0)
        charts.addWidget(self.severity_chart, 0, 1)
        charts.addWidget(self.top_src_chart, 1, 0)
        charts.addWidget(self.top_port_chart, 1, 1)
        charts.addWidget(self.attack_chain_chart, 2, 0)
        charts.addWidget(self.anomaly_score_chart, 2, 1)
        charts.setColumnStretch(0, 1)
        charts.setColumnStretch(1, 1)
        for row in range(3):
            charts.setRowStretch(row, 1)

        self.trend_title = QLabel("Alert trend")
        self.trend_title.setObjectName("SectionTitle")
        self.trend_table = QTableWidget(0, 4)
        self.trend_table.setHorizontalHeaderLabels(["Bucket", "Alerts", "Spike", "Threshold"])
        configure_responsive_table(self.trend_table, stretch_columns=(0,), resize_to_contents_columns=(1, 2, 3))
        self.trend_table.setMinimumHeight(110)

        self.timeline_title = QLabel("Attack chain timeline")
        self.timeline_title.setObjectName("SectionTitle")
        self.attack_timeline = QTableWidget(0, 4)
        self.attack_timeline.setHorizontalHeaderLabels(["Source", "Timeline", "Risk", "Alerts"])
        configure_responsive_table(self.attack_timeline, stretch_columns=(1,), resize_to_contents_columns=(2, 3))
        self.attack_timeline.setMinimumHeight(110)

        self.host_risk_title = QLabel("High-risk hosts")
        self.host_risk_title.setObjectName("SectionTitle")
        self.host_risk_table = QTableWidget(0, 7)
        self.host_risk_table.setHorizontalHeaderLabels(["Host", "Score", "Severity", "Chain", "Baseline", "Asset", "Reasons"])
        configure_responsive_table(self.host_risk_table, stretch_columns=(0, 6), resize_to_contents_columns=(1, 2, 3, 4, 5))
        self.host_risk_table.setMinimumHeight(110)

        self.baseline_title = QLabel("Baseline summary")
        self.baseline_title.setObjectName("SectionTitle")
        self.baseline_table = QTableWidget(0, 7)
        self.baseline_table.setHorizontalHeaderLabels(
            ["Source", "Packets", "Connections", "Destinations", "Ports", "Bytes", "External ratio"]
        )
        configure_responsive_table(self.baseline_table, stretch_columns=(0,), resize_to_contents_columns=(1, 2, 3, 4, 5, 6))
        self.baseline_table.setMinimumHeight(110)

        layout.addLayout(toolbar, 0)
        layout.addLayout(cards, 0)
        layout.addLayout(charts, 3)
        layout.addWidget(self.trend_title)
        layout.addWidget(self.trend_table, 1)
        layout.addWidget(self.timeline_title)
        layout.addWidget(self.attack_timeline, 1)
        layout.addWidget(self.host_risk_title)
        layout.addWidget(self.host_risk_table, 1)
        layout.addWidget(self.baseline_title)
        layout.addWidget(self.baseline_table, 1)

        self.refresh_button.clicked.connect(self.refresh)
        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        packet_count = self.packet_repository.count()
        alert_count = self.alert_repository.count()
        severity_distribution = self.alert_repository.count_by_severity()
        high_count = severity_distribution.get("HIGH", 0) + severity_distribution.get("CRITICAL", 0)

        self.packet_card.set_value(packet_count)
        self.alert_card.set_value(alert_count)
        self.high_card.set_value(high_count)
        self.status_card.set_value("Detecting" if packet_count else "Waiting")

        alerts = self.alert_repository.list_all(limit=1000)
        chains = self.attack_chain_analyzer.analyze(alerts)
        self.protocol_chart.set_data(self.packet_repository.protocol_distribution())
        self.severity_chart.set_data(severity_distribution)
        self.top_src_chart.set_data(self.packet_repository.top_src_ips())
        self.top_port_chart.set_data(self.packet_repository.top_dst_ports())
        self.attack_chain_chart.set_data(self.attack_chain_analyzer.stage_distribution(alerts))
        self.anomaly_score_chart.set_data(self._recent_anomaly_scores())
        self._render_alert_trend()
        self._render_attack_timeline(chains)
        baseline_records = self._refresh_baseline_summary()
        self._render_host_risk(alerts, chains, baseline_records)

    def _render_alert_trend(self) -> None:
        points = self.alert_trend_analyzer.analyze(self.alert_repository.count_by_time_bucket(bucket="hour", limit=24))
        self.trend_table.setRowCount(len(points))
        for row, point in enumerate(points):
            self._set_trend_row(row, point)

        self.trend_table.setColumnWidth(0, 150)
        self.trend_table.setColumnWidth(1, 80)
        self.trend_table.setColumnWidth(2, 80)
        self.trend_table.resizeRowsToContents()

    def _set_trend_row(self, row: int, point: AlertTrendPoint) -> None:
        values = [point.bucket, str(point.count), "Spike" if point.is_spike else "", f"{point.threshold:.1f}"]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip("Alert count is above historical mean plus two standard deviations." if point.is_spike else value)
            if point.is_spike:
                item.setBackground(QColor("#fee2e2"))
            self.trend_table.setItem(row, column, item)

    def _render_attack_timeline(self, chains: list[AttackChain]) -> None:
        top_chains = chains[:6]
        self.attack_timeline.setRowCount(len(top_chains))
        for row, chain in enumerate(top_chains):
            values = [chain.source_ip, chain.summary, str(chain.risk_score), str(len(chain.alerts))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.attack_timeline.setItem(row, column, item)

        self.attack_timeline.setColumnWidth(0, 150)
        self.attack_timeline.setColumnWidth(2, 70)
        self.attack_timeline.setColumnWidth(3, 70)
        self.attack_timeline.resizeRowsToContents()

    def _render_host_risk(
        self,
        alerts: list[AlertRecord],
        chains: list[AttackChain],
        baseline_records: list[BaselineRecord],
    ) -> None:
        risks = self.host_risk_scorer.score_hosts(alerts, chains, baseline_records, limit=8)
        self.host_risk_table.setRowCount(len(risks))
        for row, risk in enumerate(risks):
            self._set_host_risk_row(row, risk)

        self.host_risk_table.setColumnWidth(0, 150)
        self.host_risk_table.setColumnWidth(1, 70)
        self.host_risk_table.setColumnWidth(2, 80)
        self.host_risk_table.setColumnWidth(3, 70)
        self.host_risk_table.setColumnWidth(4, 80)
        self.host_risk_table.setColumnWidth(5, 70)
        self.host_risk_table.resizeRowsToContents()

    def _set_host_risk_row(self, row: int, risk: HostRiskBreakdown) -> None:
        reasons = "; ".join(risk.reasons)
        values = [
            risk.source_ip,
            str(risk.score),
            str(risk.severity_score),
            str(risk.chain_score),
            str(risk.baseline_score),
            str(risk.asset_score),
            reasons,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self.host_risk_table.setItem(row, column, item)

    def _recent_anomaly_scores(self) -> list[tuple[str, int]]:
        detector = SimpleAnomalyDetector()
        rows: list[tuple[str, int]] = []
        packets = self.packet_repository.list_recent(limit=30)
        for index, packet in enumerate(packets[-20:], start=1):
            score = int(detector.score_packet(packet).score)
            rows.append((f"{index}. {packet.protocol}", score))
        return rows

    def _refresh_baseline_summary(self) -> list[BaselineRecord]:
        manager = BaselineManager(window_seconds=60)
        for packet in self.packet_repository.list_recent(limit=1000):
            manager.update(packet)
        records = manager.all_current_records()
        self.baseline_repository.upsert_many(records)
        records = self.baseline_repository.list_all(limit=8)
        self._render_baseline_summary(records)
        return records

    def _render_baseline_summary(self, records: list[BaselineRecord]) -> None:
        self.baseline_table.setRowCount(len(records))
        for row, record in enumerate(records):
            values = [
                record.src_ip,
                str(record.packet_count),
                str(record.connection_count),
                str(record.unique_dst_ips),
                str(record.unique_dst_ports),
                str(record.bytes_per_window),
                f"{record.internal_to_external_ratio:.1%}",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.baseline_table.setItem(row, column, item)

        self.baseline_table.setColumnWidth(0, 150)
        self.baseline_table.setColumnWidth(1, 80)
        self.baseline_table.setColumnWidth(2, 100)
        self.baseline_table.setColumnWidth(3, 110)
        self.baseline_table.setColumnWidth(4, 70)
        self.baseline_table.setColumnWidth(5, 90)
        self.baseline_table.resizeRowsToContents()
