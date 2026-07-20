from __future__ import annotations

from models import PacketRecord


EPHEMERAL_PORT_START = 49152


def is_likely_server_response(packet: PacketRecord) -> bool:
    """Return whether packet ports and flags resemble server-to-client traffic."""
    if packet.src_port is None or packet.dst_port is None:
        return False

    protocol = (packet.protocol or "").upper()
    flags = (packet.tcp_flags or "").upper()
    if protocol in {"TCP", "HTTP"} and flags:
        return "A" in flags

    return packet.src_port < EPHEMERAL_PORT_START <= packet.dst_port


def is_connection_probe(packet: PacketRecord) -> bool:
    """Keep connection initiations while excluding replies to ephemeral ports."""
    protocol = (packet.protocol or "").upper()
    flags = (packet.tcp_flags or "").upper()
    if protocol in {"TCP", "HTTP"} and flags:
        return "S" in flags and "A" not in flags
    return not is_likely_server_response(packet)
