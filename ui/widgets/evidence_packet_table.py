from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableWidget, QTableWidgetItem

from models import PacketRecord
from ui.styles import configure_responsive_table


class EvidencePacketTable(QTableWidget):
    block_requested = Signal(str, str, str)
    packet_activated = Signal(object)

    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(
            ["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Length", "Summary"]
        )
        configure_responsive_table(self, stretch_columns=(7,), resize_to_contents_columns=(3, 4, 5, 6))
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._open_context_menu)
        self.itemDoubleClicked.connect(self._emit_packet)

    def set_packets(self, packets: list[PacketRecord]) -> None:
        self.setUpdatesEnabled(False)
        self.setRowCount(len(packets))
        try:
            for row, packet in enumerate(packets):
                values = [
                    packet.timestamp,
                    packet.src_ip or "",
                    packet.dst_ip or "",
                    packet.protocol,
                    "" if packet.src_port is None else str(packet.src_port),
                    "" if packet.dst_port is None else str(packet.dst_port),
                    str(packet.length),
                    packet.raw_summary,
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    item.setData(Qt.UserRole, packet)
                    self.setItem(row, column, item)
        finally:
            self.setUpdatesEnabled(True)

    def _open_context_menu(self, position: QPoint) -> None:
        item = self.itemAt(position)
        packet = item.data(Qt.UserRole) if item else None
        if not isinstance(packet, PacketRecord):
            return
        menu = QMenu(self)
        actions: list[tuple[object, str, str]] = []
        for label, field, value in (
            ("Block source IP", "SRC_IP", packet.src_ip),
            ("Block destination IP", "DST_IP", packet.dst_ip),
            ("Block source port", "SRC_PORT", packet.src_port),
            ("Block destination port", "DST_PORT", packet.dst_port),
        ):
            if value is None or value == "":
                continue
            action = menu.addAction(f"{label}: {value}")
            actions.append((action, field, str(value)))
        selected = menu.exec(self.viewport().mapToGlobal(position))
        for action, field, value in actions:
            if selected is action:
                packet_protocol = packet.protocol.upper()
                if packet_protocol in {"TCP", "HTTP", "HTTPS", "TLS"}:
                    protocol = "TCP"
                elif packet_protocol in {"UDP", "QUIC", "DHCP", "MDNS", "LLMNR", "NBNS", "NTP"}:
                    protocol = "UDP"
                else:
                    protocol = "ANY"
                self.block_requested.emit(field, value, protocol)
                return

    def _emit_packet(self, item: QTableWidgetItem) -> None:
        packet = item.data(Qt.UserRole)
        if isinstance(packet, PacketRecord):
            self.packet_activated.emit(packet)
