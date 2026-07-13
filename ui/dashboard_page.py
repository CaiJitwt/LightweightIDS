from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
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
from storage.analyst_repositories import AssetRepository
from storage.repositories import AlertRepository, BaselineRepository, PacketRepository
from ui.i18n import locale_manager
from ui.widgets.chart_widget import ChartWidget
from ui.widgets.statistic_card import StatisticCard
from ui.styles import apply_importance_style, apply_score_style, apply_semantic_style, configure_responsive_table


class DashboardPage(QWidget):
    host_activated = Signal(str)
    AUTO_REFRESH_INTERVAL_MS = 5_000

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)
        self.baseline_repository = BaselineRepository(database)
        self.asset_repository = AssetRepository(database)
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.host_risk_scorer = HostRiskScorer(self.attack_chain_analyzer)
        self.alert_trend_analyzer = AlertTrendAnalyzer()
        self._refreshing = False
        self._retranslating = False
        self._last_snapshot: tuple[int, int] | None = None

        self._lm = locale_manager()
        self._lm.locale_changed.connect(self.retranslate_ui)

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
        self.refresh_button = QPushButton(self._lm.tr("page.dashboard.refresh_statistics"))
        self.reset_button = QPushButton(self._lm.tr("page.dashboard.reset_statistics"))
        self.auto_refresh_checkbox = QCheckBox(self._lm.tr("page.dashboard.auto_refresh"))
        self.auto_refresh_checkbox.setChecked(True)
        self.auto_refresh_checkbox.setToolTip(self._lm.tr("page.dashboard.auto_refresh_tooltip"))
        self.refresh_status_label = QLabel(self._lm.tr("page.dashboard.last_refreshed_never"))
        self.refresh_status_label.setObjectName("PageHint")
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.reset_button)
        toolbar.addWidget(self.auto_refresh_checkbox)
        toolbar.addWidget(self.refresh_status_label)
        toolbar.addStretch()

        cards = QGridLayout()
        cards.setSpacing(12)
        self.packet_card = StatisticCard(self._lm.tr("page.dashboard.card.processed_packets"), "0", tone="blue")
        self.alert_card = StatisticCard(self._lm.tr("page.dashboard.card.total_alerts"), "0", tone="violet")
        self.high_card = StatisticCard(self._lm.tr("page.dashboard.card.high_risk_alerts"), "0", tone="red")
        self.status_card = StatisticCard(self._lm.tr("page.dashboard.card.detection_status"), self._lm.tr("common.waiting"), tone="green")
        cards.addWidget(self.packet_card, 0, 0)
        cards.addWidget(self.alert_card, 0, 1)
        cards.addWidget(self.high_card, 0, 2)
        cards.addWidget(self.status_card, 0, 3)
        for column in range(4):
            cards.setColumnStretch(column, 1)

        charts = QGridLayout()
        charts.setSpacing(12)
        self.protocol_chart = ChartWidget(self._lm.tr("page.dashboard.chart.protocol_distribution"))
        self.severity_chart = ChartWidget(self._lm.tr("page.dashboard.chart.alert_severity"))
        self.top_src_chart = ChartWidget(self._lm.tr("page.dashboard.chart.top_src_ips"))
        self.top_port_chart = ChartWidget(self._lm.tr("page.dashboard.chart.top_dst_ports"))
        self.attack_chain_chart = ChartWidget(self._lm.tr("page.dashboard.chart.attack_chain_stages"))
        self.anomaly_score_chart = ChartWidget(self._lm.tr("page.dashboard.chart.anomaly_score_trend"))
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

        self.trend_title = QLabel(self._lm.tr("page.dashboard.alert_trend"))
        self.trend_title.setObjectName("SectionTitle")
        self.trend_table = QTableWidget(0, 4)
        self.trend_table.setHorizontalHeaderLabels([
            self._lm.tr("table.bucket"),
            self._lm.tr("table.alerts"),
            self._lm.tr("table.spike_indicator"),
            self._lm.tr("table.threshold"),
        ])
        configure_responsive_table(self.trend_table, stretch_columns=(0,), resize_to_contents_columns=(1, 2, 3))
        self.trend_table.setMinimumHeight(110)

        self.timeline_title = QLabel(self._lm.tr("page.dashboard.attack_chain_timeline"))
        self.timeline_title.setObjectName("SectionTitle")
        self.attack_timeline = QTableWidget(0, 4)
        self.attack_timeline.setHorizontalHeaderLabels([
            self._lm.tr("common.source"),
            self._lm.tr("table.summary"),
            self._lm.tr("common.risk"),
            self._lm.tr("table.alerts"),
        ])
        configure_responsive_table(self.attack_timeline, stretch_columns=(1,), resize_to_contents_columns=(2, 3))
        self.attack_timeline.setMinimumHeight(110)

        self.host_risk_title = QLabel(self._lm.tr("page.dashboard.high_risk_hosts"))
        self.host_risk_title.setObjectName("SectionTitle")
        self.host_risk_table = QTableWidget(0, 7)
        self.host_risk_table.setHorizontalHeaderLabels([
            self._lm.tr("table.host"),
            self._lm.tr("common.score"),
            self._lm.tr("common.severity"),
            "Chain",
            "Baseline",
            "Asset",
            self._lm.tr("table.reasons"),
        ])
        configure_responsive_table(self.host_risk_table, stretch_columns=(0, 6), resize_to_contents_columns=(1, 2, 3, 4, 5))
        self.host_risk_table.setMinimumHeight(110)

        self.baseline_title = QLabel(self._lm.tr("page.dashboard.baseline_summary"))
        self.baseline_title.setObjectName("SectionTitle")
        self.baseline_table = QTableWidget(0, 7)
        self.baseline_table.setHorizontalHeaderLabels([
            self._lm.tr("common.source"),
            self._lm.tr("table.packets"),
            self._lm.tr("table.connections"),
            self._lm.tr("table.destinations"),
            self._lm.tr("table.ports"),
            self._lm.tr("table.bytes"),
            self._lm.tr("table.external_ratio"),
        ])
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

        self.refresh_button.clicked.connect(self.handle_refresh_clicked)
        self.reset_button.clicked.connect(self.handle_reset_clicked)
        self.auto_refresh_checkbox.toggled.connect(self._sync_auto_refresh_timer)
        self.host_risk_table.cellDoubleClicked.connect(self._activate_host)
        self.auto_refresh_timer = QTimer(self)
        self.auto_refresh_timer.setInterval(self.AUTO_REFRESH_INTERVAL_MS)
        self.auto_refresh_timer.timeout.connect(self._auto_refresh)
        self.refresh()

    def retranslate_ui(self) -> None:
        """Re-apply all translatable strings after a locale change."""
        self._retranslating = True
        try:
            # -- toolbar --
            self.refresh_button.setText(self._lm.tr("page.dashboard.refresh_statistics"))
            self.reset_button.setText(self._lm.tr("page.dashboard.reset_statistics"))
            self.auto_refresh_checkbox.setText(self._lm.tr("page.dashboard.auto_refresh"))
            self.auto_refresh_checkbox.setToolTip(self._lm.tr("page.dashboard.auto_refresh_tooltip"))

            # -- statistic cards (title labels are layout children) --
            card_keys = [
                (self.packet_card, "page.dashboard.card.processed_packets"),
                (self.alert_card, "page.dashboard.card.total_alerts"),
                (self.high_card, "page.dashboard.card.high_risk_alerts"),
                (self.status_card, "page.dashboard.card.detection_status"),
            ]
            for card, key in card_keys:
                title_label = card.layout().itemAt(0).widget()
                if isinstance(title_label, QLabel):
                    title_label.setText(self._lm.tr(key))

            # -- chart widget titles --
            chart_title_pairs = [
                (self.protocol_chart, "page.dashboard.chart.protocol_distribution"),
                (self.severity_chart, "page.dashboard.chart.alert_severity"),
                (self.top_src_chart, "page.dashboard.chart.top_src_ips"),
                (self.top_port_chart, "page.dashboard.chart.top_dst_ports"),
                (self.attack_chain_chart, "page.dashboard.chart.attack_chain_stages"),
                (self.anomaly_score_chart, "page.dashboard.chart.anomaly_score_trend"),
            ]
            chart_headers = [
                self._lm.tr("table.item"),
                self._lm.tr("table.value"),
                self._lm.tr("table.percent"),
            ]
            for chart, key in chart_title_pairs:
                chart.title_label.setText(self._lm.tr(key))
                chart.table.setHorizontalHeaderLabels(chart_headers)

            # -- section titles --
            self.trend_title.setText(self._lm.tr("page.dashboard.alert_trend"))
            self.timeline_title.setText(self._lm.tr("page.dashboard.attack_chain_timeline"))
            self.host_risk_title.setText(self._lm.tr("page.dashboard.high_risk_hosts"))
            self.baseline_title.setText(self._lm.tr("page.dashboard.baseline_summary"))

            # -- table headers --
            self.trend_table.setHorizontalHeaderLabels([
                self._lm.tr("table.bucket"),
                self._lm.tr("table.alerts"),
                self._lm.tr("table.spike_indicator"),
                self._lm.tr("table.threshold"),
            ])
            self.attack_timeline.setHorizontalHeaderLabels([
                self._lm.tr("common.source"),
                self._lm.tr("table.summary"),
                self._lm.tr("common.risk"),
                self._lm.tr("table.alerts"),
            ])
            self.host_risk_table.setHorizontalHeaderLabels([
                self._lm.tr("table.host"),
                self._lm.tr("common.score"),
                self._lm.tr("common.severity"),
                "Chain",
                "Baseline",
                "Asset",
                self._lm.tr("table.reasons"),
            ])
            self.baseline_table.setHorizontalHeaderLabels([
                self._lm.tr("common.source"),
                self._lm.tr("table.packets"),
                self._lm.tr("table.connections"),
                self._lm.tr("table.destinations"),
                self._lm.tr("table.ports"),
                self._lm.tr("table.bytes"),
                self._lm.tr("table.external_ratio"),
            ])

            # -- refresh dynamic data (labels, tooltips, table content) --
            self.refresh()
        finally:
            self._retranslating = False

    def _activate_host(self, row: int, _column: int) -> None:
        item = self.host_risk_table.item(row, 0)
        if item and item.text():
            self.host_activated.emit(item.text())

    def showEvent(self, event: object) -> None:
        self.refresh()
        self._sync_auto_refresh_timer()
        super().showEvent(event)  # type: ignore[arg-type]

    def hideEvent(self, event: object) -> None:
        self.auto_refresh_timer.stop()
        super().hideEvent(event)  # type: ignore[arg-type]

    def _sync_auto_refresh_timer(self, _enabled: bool | None = None) -> None:
        if self.auto_refresh_checkbox.isChecked() and self.isVisible():
            self.auto_refresh_timer.start()
        else:
            self.auto_refresh_timer.stop()

    def _auto_refresh(self) -> None:
        try:
            self.refresh(force=False)
        except Exception as exc:
            self.refresh_status_label.setText(
                self._lm.tr("page.dashboard.auto_refresh_failed", exc=exc)
            )

    def handle_refresh_clicked(self) -> None:
        self.refresh_button.setEnabled(False)
        try:
            self.refresh()
        except Exception as exc:
            QMessageBox.warning(
                self,
                self._lm.tr("page.dashboard.refresh_failed"),
                self._lm.tr("page.dashboard.refresh_failed_msg", exc=exc),
            )
        finally:
            self.refresh_button.setEnabled(True)

    def handle_reset_clicked(self) -> None:
        answer = QMessageBox.question(
            self,
            self._lm.tr("page.dashboard.reset_title"),
            self._lm.tr("page.dashboard.reset_msg"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        self.reset_button.setEnabled(False)
        try:
            self._reset_runtime_data()
            self.refresh()
            QMessageBox.information(
                self,
                self._lm.tr("page.dashboard.reset_done"),
                self._lm.tr("page.dashboard.reset_done_msg"),
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                self._lm.tr("page.dashboard.reset_failed"),
                self._lm.tr("page.dashboard.reset_failed_msg", exc=exc),
            )
        finally:
            self.reset_button.setEnabled(True)

    def _reset_runtime_data(self) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM alerts")
            connection.execute("DELETE FROM packets")
            connection.execute("DELETE FROM baselines")
            connection.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'packets', 'baselines')")
            connection.commit()

    def refresh(self, *, force: bool = True) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        try:
            self._refresh_statistics(force=force)
        finally:
            self._refreshing = False

    def _refresh_statistics(self, *, force: bool) -> None:
        packet_count = self.packet_repository.count()
        alert_count = self.alert_repository.count()
        snapshot = (packet_count, alert_count)
        if not force and snapshot == self._last_snapshot:
            self.refresh_status_label.setText(
                self._lm.tr(
                    "page.dashboard.last_checked_no_change",
                    time=datetime.now().strftime("%H:%M:%S"),
                )
            )
            return
        severity_distribution = self.alert_repository.count_by_severity()
        high_count = severity_distribution.get("HIGH", 0) + severity_distribution.get("CRITICAL", 0)

        self.packet_card.set_value(packet_count)
        self.alert_card.set_value(alert_count)
        self.high_card.set_value(high_count)
        self.status_card.set_value(
            self._lm.tr("common.detecting") if packet_count else self._lm.tr("common.waiting")
        )

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
        self._last_snapshot = snapshot
        self.refresh_status_label.setText(
            self._lm.tr(
                "page.dashboard.last_refreshed",
                time=datetime.now().strftime("%H:%M:%S"),
            )
        )

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
        values = [
            point.bucket,
            str(point.count),
            self._lm.tr("common.spike") if point.is_spike else "",
            f"{point.threshold:.1f}",
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(
                self._lm.tr("page.dashboard.trend_spike_tooltip")
                if point.is_spike
                else value
            )
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
                if column == 2:
                    apply_score_style(item, chain.risk_score, label="Attack chain risk")
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
        risks = self.host_risk_scorer.score_hosts(
            alerts,
            chains,
            baseline_records,
            asset_importance=self.asset_repository.importance_map(),
            limit=8,
        )
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
            if column == 1:
                apply_score_style(item, risk.score)
            elif column == 5:
                apply_importance_style(item, int(risk.asset_score * 10))
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
                if column == 6:
                    direction = "OUTBOUND" if record.internal_to_external_ratio >= 0.5 else "INBOUND"
                    apply_semantic_style(item, direction, value)
                self.baseline_table.setItem(row, column, item)

        self.baseline_table.setColumnWidth(0, 150)
        self.baseline_table.setColumnWidth(1, 80)
        self.baseline_table.setColumnWidth(2, 100)
        self.baseline_table.setColumnWidth(3, 110)
        self.baseline_table.setColumnWidth(4, 70)
        self.baseline_table.setColumnWidth(5, 90)
        self.baseline_table.resizeRowsToContents()
