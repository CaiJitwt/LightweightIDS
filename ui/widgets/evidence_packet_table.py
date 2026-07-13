from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableWidget, QTableWidgetItem

from models import PacketRecord
from ui.i18n import locale_manager
from ui.styles import configure_responsive_table

_HEADERS = (
    "widget.packet_table.time",
    "widget.packet_table.source_ip",
    "widget.packet_table.destination_ip",
    "widget.packet_table.protocol",
    "widget.packet_table.source_port",
    "widget.packet_table.destination_port",
    "widget.packet_table.length",
    "widget.packet_table.summary",
)

_CONTEXT_MENU_LABELS: list[tuple[str, str]] = [
    ("widget.evidence.context_menu.block_src_ip", "SRC_IP"),
    ("widget.evidence.context_menu.block_dst_ip", "DST_IP"),
    ("widget.evidence.context_menu.block_src_port", "SRC_PORT"),
    ("widget.evidence.context_menu.block_dst_port", "DST_PORT"),
]


class EvidencePacketTable(QTableWidget):
    block_requested = Signal(str, str, str)
    packet_activated = Signal(object)

    def __init__(self) -> None:
        super().__init__(0, len(_HEADERS))
        self._lm = locale_manager()
        self._retranslating = False
        self.setHorizontalHeaderLabels([self._lm.tr(key) for key in _HEADERS])
        configure_responsive_table(self, stretch_columns=(7,), resize_to_contents_columns=(3, 4, 5, 6))
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._open_context_menu)
        self.itemDoubleClicked.connect(self._emit_packet)
        self._lm.locale_changed.connect(self.retranslate_ui)

    # ------------------------------------------------------------------
    # i18n
    # ------------------------------------------------------------------

    def retranslate_ui(self) -> None:
        self._retranslating = True
        for col, key in enumerate(_HEADERS):
            item = self.horizontalHeaderItem(col)
            if item is not None:
                item.setText(self._lm.tr(key))
        self._retranslating = False

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _open_context_menu(self, position: QPoint) -> None:
        item = self.itemAt(position)
        packet = item.data(Qt.UserRole) if item else None
        if not isinstance(packet, PacketRecord):
            return
        menu = QMenu(self)

        _value_map = {
            "SRC_IP": packet.src_ip,
            "DST_IP": packet.dst_ip,
            "SRC_PORT": packet.src_port,
            "DST_PORT": packet.dst_port,
        }

        actions: list[tuple[object, str, str]] = []
        for i18n_key, field in _CONTEXT_MENU_LABELS:
            value = _value_map[field]
            if value is None or value == "":
                continue
            label = self._lm.tr(i18n_key, value=str(value))
            action = menu.addAction(label)
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

    # ------------------------------------------------------------------
    # Double-click → detail
    # ------------------------------------------------------------------

    def _emit_packet(self, item: QTableWidgetItem) -> None:
        packet = item.data(Qt.UserRole)
        if isinstance(packet, PacketRecord):
            self.packet_activated.emit(packet)
