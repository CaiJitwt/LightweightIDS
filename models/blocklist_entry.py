from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import ClassVar, Optional

from models.packet_record import PacketRecord


@dataclass(slots=True)
class BlocklistEntry:
    VALID_KINDS: ClassVar[set[str]] = {"IP", "PORT"}
    VALID_FIELDS: ClassVar[set[str]] = {"SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT"}
    VALID_PROTOCOLS: ClassVar[set[str]] = {"ANY", "TCP", "UDP"}

    id: Optional[int] = None
    kind: str = "IP"
    value: str = ""
    field: str = "SRC_IP"
    protocol: str = "ANY"
    enabled: bool = True
    enforcement_status: str = "Pending"
    enforcement_error: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.kind = self.kind.upper()
        self.field = self.field.upper()
        self.protocol = self.protocol.upper()
        if self.kind not in self.VALID_KINDS:
            raise ValueError(f"Invalid blocklist kind: {self.kind}")
        if self.field not in self.VALID_FIELDS:
            raise ValueError(f"Invalid blocklist field: {self.field}")
        if self.protocol not in self.VALID_PROTOCOLS:
            raise ValueError(f"Invalid blocklist protocol: {self.protocol}")
        if self.kind == "IP":
            if self.field not in {"SRC_IP", "DST_IP"}:
                raise ValueError("IP entries require an IP field")
            self.value = str(ip_address(self.value.strip()))
        else:
            if self.field not in {"SRC_PORT", "DST_PORT"}:
                raise ValueError("Port entries require a port field")
            port = int(self.value)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535")
            self.value = str(port)

    def matches(self, packet: PacketRecord) -> bool:
        if not self.enabled:
            return False
        packet_protocol = packet.protocol.upper()
        tcp_protocols = {"TCP", "HTTP", "HTTPS", "TLS"}
        udp_protocols = {"UDP", "QUIC", "DHCP", "MDNS", "LLMNR", "NBNS", "NTP"}
        if self.protocol == "TCP" and packet_protocol not in tcp_protocols:
            return False
        if self.protocol == "UDP" and packet_protocol not in udp_protocols:
            return False
        values = {
            "SRC_IP": packet.src_ip,
            "DST_IP": packet.dst_ip,
            "SRC_PORT": None if packet.src_port is None else str(packet.src_port),
            "DST_PORT": None if packet.dst_port is None else str(packet.dst_port),
        }
        return values[self.field] == self.value
