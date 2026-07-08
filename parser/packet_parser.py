from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from models import PacketRecord


class PacketParser:
    def parse(self, packet: object) -> PacketRecord:
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.packet import Raw
        except ImportError as exc:
            raise RuntimeError("缺少 Scapy。请先安装 requirements.txt 中的依赖。") from exc

        timestamp = self._format_timestamp(getattr(packet, "time", None))
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        dns_query: Optional[str] = None
        http_method: Optional[str] = None
        http_host: Optional[str] = None
        http_path: Optional[str] = None
        protocol = "UNKNOWN"

        if self._has_layer(packet, IP):
            ip_layer = packet[IP]  # type: ignore[index]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif self._has_layer(packet, IPv6):
            ip_layer = packet[IPv6]  # type: ignore[index]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)

        if self._has_layer(packet, TCP):
            tcp_layer = packet[TCP]  # type: ignore[index]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
        elif self._has_layer(packet, UDP):
            udp_layer = packet[UDP]  # type: ignore[index]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif self._has_layer(packet, ICMP):
            protocol = "ICMP"

        if self._has_layer(packet, DNS):
            protocol = "DNS"
            if self._has_layer(packet, DNSQR):
                dns_query = self._decode_bytes(packet[DNSQR].qname).rstrip(".")  # type: ignore[index]

        payload_text = ""
        if self._has_layer(packet, Raw):
            payload_text = self._decode_bytes(bytes(packet[Raw].load))  # type: ignore[index]

        if self._looks_like_http(src_port, dst_port, payload_text):
            protocol = "HTTP"
            http_method, http_host, http_path = self._parse_http_payload(payload_text)

        return PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(packet) if hasattr(packet, "__len__") else 0,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
            http_method=http_method,
            http_host=http_host,
            http_path=http_path,
            raw_summary=self._packet_summary(packet),
        )

    def _format_timestamp(self, value: Any) -> str:
        try:
            return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except (TypeError, ValueError, OSError):
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _has_layer(self, packet: object, layer: object) -> bool:
        try:
            return bool(packet.haslayer(layer))  # type: ignore[attr-defined]
        except Exception:
            return False

    def _decode_bytes(self, value: bytes | str | object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _looks_like_http(self, src_port: Optional[int], dst_port: Optional[int], payload: str) -> bool:
        http_ports = {80, 8000, 8080, 8888}
        if src_port not in http_ports and dst_port not in http_ports:
            return False
        return payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "))

    def _parse_http_payload(self, payload: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not payload:
            return None, None, None

        lines = payload.splitlines()
        if not lines:
            return None, None, None

        first_line_parts = lines[0].split()
        method = first_line_parts[0] if len(first_line_parts) >= 1 else None
        path = first_line_parts[1] if len(first_line_parts) >= 2 else None
        host = None

        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        return method, host, path

    def _packet_summary(self, packet: object) -> str:
        try:
            return str(packet.summary())  # type: ignore[attr-defined]
        except Exception:
            return repr(packet)
