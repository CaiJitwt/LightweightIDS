from __future__ import annotations

from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from models import PacketRecord
from ui.styles import configure_responsive_table


class PacketTable(QTableWidget):
    MAX_VISIBLE_ROWS = 2_000

    def __init__(self) -> None:
        super().__init__(0, 8)
        self.max_visible_rows = self.MAX_VISIBLE_ROWS
        self.auto_scroll = True
        self.setHorizontalHeaderLabels(
            ["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Length", "Summary"]
        )
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

    def add_packets(self, packets: list[PacketRecord]) -> None:
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
        self.setRowCount(0)

    def set_max_visible_rows(self, value: int) -> None:
        self.max_visible_rows = max(100, int(value))
        self._trim_old_rows()

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
