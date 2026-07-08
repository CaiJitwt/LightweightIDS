from __future__ import annotations

from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from models import PacketRecord


class PacketTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(
            ["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Length", "Summary"]
        )
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.setAlternatingRowColors(True)
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

        self.setSortingEnabled(False)
        start_row = self.rowCount()
        self.setRowCount(start_row + len(packets))

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

        self.resizeRowsToContents()
        self.scrollToBottom()
        self.setSortingEnabled(True)

    def clear_packets(self) -> None:
        self.setRowCount(0)
