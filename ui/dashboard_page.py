from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from storage.database import Database
from storage.repositories import AlertRepository, PacketRepository
from ui.widgets.chart_widget import ChartWidget
from ui.widgets.statistic_card import StatisticCard


class DashboardPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.packet_repository = PacketRepository(database)
        self.alert_repository = AlertRepository(database)

        layout = QVBoxLayout(self)
        layout.setSpacing(18)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("刷新统计")
        toolbar.addWidget(self.refresh_button)
        toolbar.addStretch()

        cards = QGridLayout()
        cards.setSpacing(14)
        self.packet_card = StatisticCard("已处理数据包", "0")
        self.alert_card = StatisticCard("告警总数", "0")
        self.high_card = StatisticCard("高危告警", "0")
        self.status_card = StatisticCard("检测状态", "待导入流量")
        cards.addWidget(self.packet_card, 0, 0)
        cards.addWidget(self.alert_card, 0, 1)
        cards.addWidget(self.high_card, 0, 2)
        cards.addWidget(self.status_card, 0, 3)

        charts = QGridLayout()
        charts.setSpacing(14)
        self.protocol_chart = ChartWidget("协议分布")
        self.severity_chart = ChartWidget("告警等级分布")
        self.top_src_chart = ChartWidget("Top 源 IP")
        self.top_port_chart = ChartWidget("Top 目标端口")
        charts.addWidget(self.protocol_chart, 0, 0)
        charts.addWidget(self.severity_chart, 0, 1)
        charts.addWidget(self.top_src_chart, 1, 0)
        charts.addWidget(self.top_port_chart, 1, 1)

        layout.addLayout(toolbar)
        layout.addLayout(cards)
        layout.addLayout(charts)

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
        self.status_card.set_value("已检测" if packet_count else "待导入流量")

        self.protocol_chart.set_data(self.packet_repository.protocol_distribution())
        self.severity_chart.set_data(severity_distribution)
        self.top_src_chart.set_data(self.packet_repository.top_src_ips())
        self.top_port_chart.set_data(self.packet_repository.top_dst_ports())
