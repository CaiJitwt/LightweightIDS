from __future__ import annotations

from enum import StrEnum


class ProtocolType(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    UNKNOWN = "UNKNOWN"
