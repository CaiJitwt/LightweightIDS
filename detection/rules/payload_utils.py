from __future__ import annotations

from models import PacketRecord


def packet_text(packet: PacketRecord) -> str:
    values = [
        packet.raw_summary,
        packet.dns_query,
        packet.http_method,
        packet.http_host,
        packet.http_path,
    ]
    return " ".join(value for value in values if value).lower()


def matched_keywords(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword.lower() in lowered]
