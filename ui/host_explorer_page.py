from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from detection.analysis.host_profile import HostProfileService
from models import HostSummary
from storage.database import Database
from ui.styles import (
    apply_importance_style,
    apply_score_style,
    apply_semantic_style,
    apply_severity_style,
    configure_responsive_table,
)
from ui.widgets.alert_table import AlertTable


class HostExplorerPage(QWidget):
    investigation_requested = Signal(str, str, list)

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.service = HostProfileService(database)
        self.hosts: list[HostSummary] = []
        self.current_host_ip = ""
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search IP, asset name or role")
        self.refresh_button = QPushButton("Refresh")
        self.investigate_button = QPushButton("Create investigation")
        toolbar.addWidget(self.search_input, 1)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.investigate_button)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        self.host_table = QTableWidget(0, 8)
        self.host_table.setHorizontalHeaderLabels(
            ["Host", "Name", "Role", "Risk", "Importance", "Packets", "Alerts", "Last seen"]
        )
        configure_responsive_table(
            self.host_table,
            stretch_columns=(0, 1),
            resize_to_contents_columns=(2, 3, 4, 5, 6, 7),
        )
        self.host_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.host_table.setEditTriggers(QTableWidget.NoEditTriggers)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        self.tabs = QTabWidget()
        self.overview_view = QTextEdit()
        self.overview_view.setReadOnly(True)
        self.connections_table = QTableWidget(0, 6)
        self.connections_table.setHorizontalHeaderLabels(
            ["Peer", "Direction", "Protocol", "Port", "Packets", "Last seen"]
        )
        configure_responsive_table(self.connections_table, stretch_columns=(0,), resize_to_contents_columns=(1, 2, 3, 4, 5))
        self.alert_table = AlertTable()
        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(
            ["Time", "Type", "Direction", "Peer", "Severity", "Summary"]
        )
        configure_responsive_table(self.timeline_table, stretch_columns=(3, 5), resize_to_contents_columns=(1, 2, 4))
        self.tabs.addTab(self.overview_view, "Overview")
        self.tabs.addTab(self.connections_table, "Connections")
        self.tabs.addTab(self.alert_table, "Alerts")
        self.tabs.addTab(self.timeline_table, "Timeline")
        detail_layout.addWidget(self.tabs)
        splitter.addWidget(self.host_table)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self.search_input.textChanged.connect(self.refresh)
        self.refresh_button.clicked.connect(self.refresh)
        self.investigate_button.clicked.connect(self.request_investigation)
        self.host_table.itemSelectionChanged.connect(self.render_selected_host)
        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        selected_ip = self.current_host_ip
        self.hosts = self.service.list_hosts(self.search_input.text().strip())
        self.host_table.setRowCount(len(self.hosts))
        for row, host in enumerate(self.hosts):
            values = [
                host.ip,
                host.display_name,
                host.role,
                str(host.risk_score),
                str(host.importance),
                str(host.packet_count),
                str(host.alert_count),
                host.last_seen,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, host.ip)
                if column == 2:
                    apply_semantic_style(item, host.role)
                elif column == 3:
                    apply_score_style(item, host.risk_score)
                elif column == 4:
                    apply_importance_style(item, host.importance)
                self.host_table.setItem(row, column, item)
        if selected_ip:
            self._select_row(selected_ip)
        elif self.hosts:
            self.host_table.selectRow(0)
        else:
            self.current_host_ip = ""
            self.overview_view.clear()
            self.connections_table.setRowCount(0)
            self.alert_table.set_alerts([])
            self.timeline_table.setRowCount(0)

    def select_host(self, host_ip: str) -> None:
        self.search_input.clear()
        self.current_host_ip = host_ip
        self.refresh()
        self._select_row(host_ip)

    def render_selected_host(self) -> None:
        host = self._selected_host()
        if host is None:
            return
        self.current_host_ip = host.ip
        protocols = self.service.protocol_distribution(host.ip)
        ports = self.service.port_distribution(host.ip)
        reasons = "\n".join(f"- {reason}" for reason in host.risk_reasons) or "- No notable source-host risk signals"
        self.overview_view.setPlainText(
            f"Host: {host.display_name or host.ip}\n"
            f"IP address: {host.ip}\n"
            f"Role: {host.role}\n"
            f"Asset importance: {host.importance}\n"
            f"Risk score: {host.risk_score}\n"
            f"Packets: {host.packet_count} ({host.incoming_packets} inbound, {host.outgoing_packets} outbound)\n"
            f"Alerts: {host.alert_count} ({host.critical_count} critical)\n"
            f"Last seen: {host.last_seen or 'Never'}\n\n"
            f"Protocols: {self._format_mapping(protocols)}\n"
            f"Top destination ports: {', '.join(f'{port}={count}' for port, count in ports) or 'None'}\n\n"
            f"Risk reasons:\n{reasons}"
        )
        connections = self.service.connections(host.ip)
        self.connections_table.setRowCount(len(connections))
        for row, connection in enumerate(connections):
            values = [
                connection.peer_ip,
                connection.direction,
                connection.protocol,
                "" if connection.port is None else str(connection.port),
                str(connection.packet_count),
                connection.last_seen,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column in {1, 2}:
                    apply_semantic_style(item, value)
                self.connections_table.setItem(row, column, item)

        alerts = self.service.alerts_for_host(host.ip)
        self.alert_table.set_alerts(alerts)
        events = self.service.timeline(host.ip)
        self.timeline_table.setRowCount(len(events))
        for row, event in enumerate(events):
            values = [event.timestamp, event.event_type, event.direction, event.peer_ip, event.severity, event.summary]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 4 and event.severity:
                    apply_severity_style(item, event.severity)
                elif column == 2:
                    apply_semantic_style(item, event.direction)
                self.timeline_table.setItem(row, column, item)

    def request_investigation(self) -> None:
        host = self._selected_host()
        if host is None:
            return
        summary = "; ".join(host.risk_reasons) or f"Review observed activity for {host.ip}."
        self.investigation_requested.emit(host.ip, summary, self.service.alerts_for_host(host.ip, limit=100))

    def _selected_host(self) -> HostSummary | None:
        row = self.host_table.currentRow()
        item = self.host_table.item(row, 0) if row >= 0 else None
        host_ip = item.data(Qt.UserRole) if item else None
        return next((host for host in self.hosts if host.ip == host_ip), None)

    def _select_row(self, host_ip: str) -> bool:
        for row in range(self.host_table.rowCount()):
            item = self.host_table.item(row, 0)
            if item and item.data(Qt.UserRole) == host_ip:
                self.host_table.selectRow(row)
                self.host_table.scrollToItem(item)
                return True
        return False

    def _format_mapping(self, values: dict[str, int]) -> str:
        return ", ".join(f"{key}={value}" for key, value in values.items()) or "None"
