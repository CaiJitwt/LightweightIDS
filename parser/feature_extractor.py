from __future__ import annotations

from typing import Any


class FeatureExtractor:
    """Extract numerical features from Scapy packets for ML anomaly detection."""

    def extract(self, packet: object) -> dict[str, Any]:
        features: dict[str, Any] = {}

        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.dns import DNS, DNSQR
            from scapy.packet import Raw
        except ImportError:
            return features

        # basic packet metadata
        features["length"] = len(packet) if hasattr(packet, "__len__") else 0
        features["time"] = getattr(packet, "time", None)

        # IP layer
        if self._has_layer(packet, IP):
            ip_layer = packet[IP]
            features["src_ip"] = str(ip_layer.src)
            features["dst_ip"] = str(ip_layer.dst)
            features["ip_ttl"] = int(ip_layer.ttl)
            features["ip_proto"] = int(ip_layer.proto)
        elif self._has_layer(packet, IPv6):
            ip_layer = packet[IPv6]
            features["src_ip"] = str(ip_layer.src)
            features["dst_ip"] = str(ip_layer.dst)

        # transport layer
        if self._has_layer(packet, TCP):
            tcp_layer = packet[TCP]
            features["protocol"] = "TCP"
            features["src_port"] = int(tcp_layer.sport)
            features["dst_port"] = int(tcp_layer.dport)
            features["tcp_flags"] = int(tcp_layer.flags)
            features["tcp_window"] = int(tcp_layer.window)
        elif self._has_layer(packet, UDP):
            udp_layer = packet[UDP]
            features["protocol"] = "UDP"
            features["src_port"] = int(udp_layer.sport)
            features["dst_port"] = int(udp_layer.dport)
        elif self._has_layer(packet, ICMP):
            features["protocol"] = "ICMP"
        else:
            features["protocol"] = "UNKNOWN"

        # DNS layer
        if self._has_layer(packet, DNS) and self._has_layer(packet, DNSQR):
            dnsqr = packet[DNSQR]
            qname = self._decode_bytes(getattr(dnsqr, "qname", b""))
            features["dns_query"] = qname.rstrip(".")
            features["dns_qtype"] = int(getattr(dnsqr, "qtype", 0))
            features["dns_qname_len"] = len(qname)

        # payload
        if self._has_layer(packet, Raw):
            payload = bytes(packet[Raw].load)
            features["payload_size"] = len(payload)
            features["payload_entropy"] = self._shannon_entropy(payload)

        return features

    def _has_layer(self, packet: object, layer: object) -> bool:
        try:
            return bool(packet.haslayer(layer))
        except Exception:
            return False

    def _decode_bytes(self, value: bytes | str | object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        total = len(data)
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * (p.bit_length() - 1)
        return entropy