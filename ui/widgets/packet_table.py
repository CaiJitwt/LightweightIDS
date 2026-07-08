from __future__ import annotations

from PySide6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

from models import PacketRecord


class PacketTable(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, 8)
        self.setHorizontalHeaderLabels(["时间", "源 IP", "目标 IP", "协议", "源端口", "目标端口", "长度", "摘要"])
        self.horizontalHeader().setStretchLastSection(True)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

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
                self.setItem(row, column, QTableWidgetItem(value))

        self.scrollToBottom()
        self.setSortingEnabled(True)

    def clear_packets(self) -> None:
        self.setRowCount(0)
