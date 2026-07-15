from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
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
from ui.i18n import locale_manager
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
        self._lm = locale_manager()
        self.service = HostProfileService(database)
        self.hosts: list[HostSummary] = []
        self.current_host_ip = ""
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(self._lm.tr("page.hosts.search_placeholder"))
        self.refresh_button = QPushButton(self._lm.tr("page.hosts.refresh"))
        self.investigate_button = QPushButton(self._lm.tr("page.hosts.create_investigation"))
        toolbar.addWidget(self.search_input, 1)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.investigate_button)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        self.host_table = QTableWidget(0, 8)
        self.host_table.setHorizontalHeaderLabels(
            [self._lm.tr("table.host"),
             self._lm.tr("table.name"),
             self._lm.tr("table.role"),
             self._lm.tr("table.risk"),
             self._lm.tr("table.importance"),
             self._lm.tr("table.packets"),
             self._lm.tr("table.alerts"),
             self._lm.tr("table.last_seen")]
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
            [self._lm.tr("table.peer"),
             self._lm.tr("table.direction"),
             self._lm.tr("table.protocol"),
             self._lm.tr("common.port"),
             self._lm.tr("table.packets"),
             self._lm.tr("table.last_seen")]
        )
        configure_responsive_table(self.connections_table, stretch_columns=(0,), resize_to_contents_columns=(1, 2, 3, 4, 5))
        self.alert_table = AlertTable()
        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(
            [self._lm.tr("table.time"),
             self._lm.tr("table.type"),
             self._lm.tr("table.direction"),
             self._lm.tr("table.peer"),
             self._lm.tr("table.severity"),
             self._lm.tr("table.summary")]
        )
        configure_responsive_table(self.timeline_table, stretch_columns=(3, 5), resize_to_contents_columns=(1, 2, 4))
        self.tabs.addTab(self.overview_view, self._lm.tr("page.hosts.overview_tab"))
        self.tabs.addTab(self.connections_table, self._lm.tr("page.hosts.connections_tab"))
        self.tabs.addTab(self.alert_table, self._lm.tr("page.hosts.alerts_tab"))
        self.tabs.addTab(self.timeline_table, self._lm.tr("page.hosts.timeline_tab"))
        detail_layout.addWidget(self.tabs)
        splitter.addWidget(self.host_table)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self._loaded = False
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self._do_refresh)
        self.search_input.textChanged.connect(lambda: self._debounce.start())
        self.refresh_button.clicked.connect(self._immediate_refresh)
        self.investigate_button.clicked.connect(self.request_investigation)
        self.host_table.itemSelectionChanged.connect(self.render_selected_host)
        self._lm.locale_changed.connect(self.retranslate_ui)
        self._immediate_refresh()

    def retranslate_ui(self) -> None:
        """Update all user-visible text for the current locale."""
        self.search_input.setPlaceholderText(self._lm.tr("page.hosts.search_placeholder"))
        self.refresh_button.setText(self._lm.tr("page.hosts.refresh"))
        self.investigate_button.setText(self._lm.tr("page.hosts.create_investigation"))

        self.host_table.setHorizontalHeaderLabels([
            self._lm.tr("table.host"),
            self._lm.tr("table.name"),
            self._lm.tr("table.role"),
            self._lm.tr("table.risk"),
            self._lm.tr("table.importance"),
            self._lm.tr("table.packets"),
            self._lm.tr("table.alerts"),
            self._lm.tr("table.last_seen"),
        ])
        self.connections_table.setHorizontalHeaderLabels([
            self._lm.tr("table.peer"),
            self._lm.tr("table.direction"),
            self._lm.tr("table.protocol"),
            self._lm.tr("common.port"),
            self._lm.tr("table.packets"),
            self._lm.tr("table.last_seen"),
        ])
        self.timeline_table.setHorizontalHeaderLabels([
            self._lm.tr("table.time"),
            self._lm.tr("table.type"),
            self._lm.tr("table.direction"),
            self._lm.tr("table.peer"),
            self._lm.tr("table.severity"),
            self._lm.tr("table.summary"),
        ])

        self.tabs.setTabText(0, self._lm.tr("page.hosts.overview_tab"))
        self.tabs.setTabText(1, self._lm.tr("page.hosts.connections_tab"))
        self.tabs.setTabText(2, self._lm.tr("page.hosts.alerts_tab"))
        self.tabs.setTabText(3, self._lm.tr("page.hosts.timeline_tab"))

        self.render_selected_host()

    def showEvent(self, event: object) -> None:
        if not self._loaded:
            self._immediate_refresh()
            self._loaded = True
        super().showEvent(event)  # type: ignore[arg-type]

    def _immediate_refresh(self) -> None:
        self._debounce.stop()
        self._do_refresh()

    def _do_refresh(self) -> None:
        keyword = self.search_input.text().strip()
        self.hosts = self.service.list_hosts(keyword)
        self._render_host_list()

    def refresh(self) -> None:
        self._immediate_refresh()

    def _render_host_list(self) -> None:
        selected_ip = self.current_host_ip
        self.host_table.setUpdatesEnabled(False)
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
        self.host_table.setUpdatesEnabled(True)
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
        if host.ip == self.current_host_ip:
            return
        self.current_host_ip = host.ip
        protocols = self.service.protocol_distribution(host.ip)
        ports = self.service.port_distribution(host.ip)
        reasons = "\n".join(f"- {reason}" for reason in host.risk_reasons) or self._lm.tr("page.hosts.no_risk_signals")
        template = self._lm.tr("page.hosts.overview_template")
        text = template.format(
            display_name=host.display_name or host.ip,
            ip=host.ip,
            role=host.role,
            importance=host.importance,
            risk_score=host.risk_score,
            packet_count=host.packet_count,
            incoming=host.incoming_packets,
            outgoing=host.outgoing_packets,
            alert_count=host.alert_count,
            critical_count=host.critical_count,
            last_seen=host.last_seen or self._lm.tr("common.never"),
            protocols=self._format_mapping(protocols),
            ports=", ".join(f"{port}={count}" for port, count in ports) or self._lm.tr("common.none_data"),
            reasons=reasons,
        )
        self.overview_view.setPlainText(text)
        connections = self.service.connections(host.ip)
        self.connections_table.setUpdatesEnabled(False)
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
        self.connections_table.setUpdatesEnabled(True)

        alerts = self.service.alerts_for_host(host.ip)
        self.alert_table.set_alerts(alerts)
        events = self.service.timeline(host.ip)
        self.timeline_table.setUpdatesEnabled(False)
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
        self.timeline_table.setUpdatesEnabled(True)

    def request_investigation(self) -> None:
        host = self._selected_host()
        if host is None:
            return
        summary = "; ".join(host.risk_reasons) or self._lm.tr("page.hosts.investigation_summary", ip=host.ip)
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
        return ", ".join(f"{key}={value}" for key, value in values.items()) or self._lm.tr("common.none_data")
