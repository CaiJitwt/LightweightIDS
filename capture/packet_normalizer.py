from __future__ import annotations

from models import PacketRecord
from parser.packet_parser import PacketParser


class PacketNormalizer:
    def __init__(self, parser: PacketParser | None = None) -> None:
        self.parser = parser or PacketParser()

    def normalize(self, packet: object) -> PacketRecord:
        return self.parser.parse(packet)
