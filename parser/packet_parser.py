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
            from scapy.layers.l2 import ARP, Ether
            from scapy.packet import Raw
        except ImportError as exc:
            raise RuntimeError("Scapy is missing. Please install the dependencies from requirements.txt.") from exc

        packet = self._decode_raw_ethernet_frame(packet, Raw, Ether)
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

        if self._has_layer(packet, IP):
            ip_layer = packet[IP]  # type: ignore[index]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif self._has_layer(packet, IPv6):
            ip_layer = packet[IPv6]  # type: ignore[index]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif self._has_layer(packet, ARP):
            arp_layer = packet[ARP]  # type: ignore[index]
            src_ip = str(getattr(arp_layer, "psrc", "") or "")
            dst_ip = str(getattr(arp_layer, "pdst", "") or "")

        if self._has_layer(packet, TCP):
            tcp_layer = packet[TCP]  # type: ignore[index]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
        elif self._has_layer(packet, UDP):
            udp_layer = packet[UDP]  # type: ignore[index]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        payload_text = ""
        if self._has_layer(packet, Raw):
            payload_text = self._decode_bytes(bytes(packet[Raw].load))  # type: ignore[index]

        protocol = self._detect_protocol(packet, src_port, dst_port, payload_text)

        if self._has_layer(packet, DNS) and self._has_layer(packet, DNSQR):
            dns_query = self._decode_bytes(packet[DNSQR].qname).rstrip(".")  # type: ignore[index]

        if protocol == "HTTP":
            http_method, http_host, http_path = self._parse_http_payload(payload_text)

        return PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip or None,
            dst_ip=dst_ip or None,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(packet) if hasattr(packet, "__len__") else 0,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
            http_method=http_method,
            http_host=http_host,
            http_path=http_path,
            raw_summary=self._packet_summary(packet, payload_text),
        )

    def _detect_protocol(self, packet: object, src_port: Optional[int], dst_port: Optional[int], payload: str) -> str:
        try:
            from scapy.layers.dns import DNS
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP
        except ImportError:
            return "UNKNOWN"

        if self._has_layer(packet, ARP):
            return "ARP"
        if self._has_layer(packet, DNS) or 53 in {src_port, dst_port}:
            return "DNS"
        if self._looks_like_tls(payload):
            return "TLS"
        if self._looks_like_http(src_port, dst_port, payload):
            return "HTTP"
        if self._has_layer(packet, TCP):
            if 443 in {src_port, dst_port}:
                return "HTTPS"
            return "TCP"
        if self._has_layer(packet, UDP):
            if 67 in {src_port, dst_port} or 68 in {src_port, dst_port}:
                return "DHCP"
            if 5353 in {src_port, dst_port}:
                return "MDNS"
            if 5355 in {src_port, dst_port}:
                return "LLMNR"
            if 137 in {src_port, dst_port}:
                return "NBNS"
            if 123 in {src_port, dst_port}:
                return "NTP"
            if 443 in {src_port, dst_port}:
                return "QUIC"
            return "UDP"
        if self._has_layer(packet, ICMP):
            return "ICMP"
        if self._has_icmpv6(packet):
            return "ICMPv6"
        if self._has_layer(packet, IPv6):
            return "IPv6"
        if self._has_layer(packet, IP):
            return "IP"
        return self._first_meaningful_layer_name(packet)

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

    def _decode_raw_ethernet_frame(self, packet: object, raw_layer: object, ether_layer: object) -> object:
        if self._layer_names(packet) != ["Raw"]:
            return packet

        try:
            frame = bytes(packet[raw_layer].load)  # type: ignore[index]
        except Exception:
            return packet

        if len(frame) < 14 or int.from_bytes(frame[12:14], "big") < 0x0600:
            return packet

        try:
            decoded = ether_layer(frame)  # type: ignore[operator]
        except Exception:
            return packet

        if self._layer_names(decoded) in (["Ether"], ["Ether", "Raw"]):
            return packet

        original_time = getattr(packet, "time", None)
        if original_time is not None:
            decoded.time = original_time  # type: ignore[attr-defined]
        return decoded

    def _has_icmpv6(self, packet: object) -> bool:
        for layer_name in self._layer_names(packet):
            if layer_name.startswith("ICMPv6"):
                return True
        return False

    def _first_meaningful_layer_name(self, packet: object) -> str:
        ignored = {"Ether", "CookedLinux", "Padding", "Raw"}
        for layer_name in self._layer_names(packet):
            if layer_name not in ignored:
                return layer_name.upper()
        return "UNKNOWN"

    def _layer_names(self, packet: object) -> list[str]:
        try:
            return [layer.__name__ for layer in packet.layers()]  # type: ignore[attr-defined]
        except Exception:
            return []

    def _decode_bytes(self, value: bytes | str | object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _looks_like_http(self, src_port: Optional[int], dst_port: Optional[int], payload: str) -> bool:
        http_ports = {80, 8000, 8080, 8888}
        if src_port not in http_ports and dst_port not in http_ports:
            return False
        return payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "))

    def _looks_like_tls(self, payload: str) -> bool:
        lowered = payload.lower()
        tls_record = (
            len(payload) >= 3
            and payload[0] in {"\x14", "\x15", "\x16", "\x17"}
            and payload[1] == "\x03"
            and payload[2] in {"\x00", "\x01", "\x02", "\x03", "\x04"}
        )
        return tls_record or "client hello" in lowered or "server hello" in lowered

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

    def _packet_summary(self, packet: object, payload_text: str = "") -> str:
        try:
            summary = str(packet.summary())  # type: ignore[attr-defined]
        except Exception:
            summary = repr(packet)

        if not payload_text:
            return summary

        preview = " ".join(payload_text.replace("\x00", " ").split())
        if not preview:
            return summary
        if len(preview) > 240:
            preview = preview[:240] + "..."
        return f"{summary} | payload={preview}"
