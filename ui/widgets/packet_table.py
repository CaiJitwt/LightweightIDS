from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from models import PacketRecord
from ui.i18n import LocaleManager, locale_manager
from ui.styles import configure_responsive_table


class PacketTable(QTableWidget):
    MAX_VISIBLE_ROWS = 500
    MAX_BUFFERED_PACKETS = 2_000

    def __init__(self, _lm: LocaleManager | None = None) -> None:
        super().__init__(0, 8)
        self._lm = _lm or locale_manager()
        self.max_visible_rows = self.MAX_VISIBLE_ROWS
        self.auto_scroll = True
        self._packets: list[PacketRecord] = []
        self._packet_filter: Callable[[PacketRecord], bool] | None = None

        self.retranslate_ui()
        self._lm.locale_changed.connect(self.retranslate_ui)

        configure_responsive_table(self, stretch_columns=(7,), resize_to_contents_columns=(3, 4, 5, 6))
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setWordWrap(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setColumnWidth(0, 170)
        self.setColumnWidth(1, 130)
        self.setColumnWidth(2, 140)
        self.setColumnWidth(3, 90)
        self.setColumnWidth(4, 100)
        self.setColumnWidth(5, 120)
        self.setColumnWidth(6, 70)

    def retranslate_ui(self) -> None:
        """Refresh all user-visible text from the locale manager."""
        self.setHorizontalHeaderLabels(
            [
                self._lm.tr("widget.packet_table.time"),
                self._lm.tr("widget.packet_table.source_ip"),
                self._lm.tr("widget.packet_table.destination_ip"),
                self._lm.tr("widget.packet_table.protocol"),
                self._lm.tr("widget.packet_table.source_port"),
                self._lm.tr("widget.packet_table.destination_port"),
                self._lm.tr("widget.packet_table.length"),
                self._lm.tr("widget.packet_table.summary"),
            ]
        )

    def add_packets(self, packets: list[PacketRecord]) -> int:
        if not packets:
            return self.rowCount()

        self._packets.extend(packets)
        overflow = len(self._packets) - self.MAX_BUFFERED_PACKETS
        if overflow > 0:
            del self._packets[:overflow]

        visible_packets = [packet for packet in packets if self._matches_filter(packet)]
        self._append_packet_rows(visible_packets)
        return self.rowCount()

    def _append_packet_rows(self, packets: list[PacketRecord]) -> None:
        if not packets:
            return

        sorting_enabled = self.isSortingEnabled()
        self.setSortingEnabled(False)
        self.setUpdatesEnabled(False)
        start_row = self.rowCount()
        self.setRowCount(start_row + len(packets))

        try:
            for offset, packet in enumerate(packets):
                row = start_row + offset
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
                    self.setItem(row, column, item)
            self._trim_old_rows()
        finally:
            self.setUpdatesEnabled(True)
            self.setSortingEnabled(sorting_enabled)
            if self.auto_scroll:
                self.scrollToBottom()

    def clear_packets(self) -> None:
        self._packets.clear()
        self.setRowCount(0)

    def set_max_visible_rows(self, value: int) -> None:
        self.max_visible_rows = max(100, int(value))
        self._rebuild_visible_rows()

    def set_packet_filter(self, packet_filter: Callable[[PacketRecord], bool] | None) -> int:
        self._packet_filter = packet_filter
        self._rebuild_visible_rows()
        return self.rowCount()

    def buffered_packet_count(self) -> int:
        return len(self._packets)

    def set_auto_scroll(self, enabled: bool) -> None:
        self.auto_scroll = enabled
        if enabled:
            self.scrollToBottom()

    def _trim_old_rows(self) -> None:
        overflow = self.rowCount() - self.max_visible_rows
        if overflow <= 0:
            return
        for _ in range(overflow):
            self.removeRow(0)

    def _matches_filter(self, packet: PacketRecord) -> bool:
        return self._packet_filter is None or self._packet_filter(packet)

    def _rebuild_visible_rows(self) -> None:
        matching_packets = [packet for packet in self._packets if self._matches_filter(packet)]
        visible_packets = matching_packets[-self.max_visible_rows :]
        self.setRowCount(0)
        self._append_packet_rows(visible_packets)
