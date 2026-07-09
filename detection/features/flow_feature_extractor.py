from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import time

from models import PacketRecord


SENSITIVE_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 6379, 9200}


@dataclass(slots=True)
class FlowFeature:
    src_ip: str
    dst_ip: str
    window_start: float
    window_seconds: int
    packet_count: int = 0
    byte_count: int = 0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    syn_count: int = 0
    icmp_count: int = 0
    dns_query_count: int = 0
    sensitive_port_count: int = 0
    http_indicator_count: int = 0

    def vector(self) -> list[float]:
        return [
            float(self.packet_count),
            float(self.byte_count),
            float(self.unique_dst_ports),
            float(self.unique_dst_ips),
            float(self.syn_count),
            float(self.icmp_count),
            float(self.dns_query_count),
            float(self.sensitive_port_count),
            float(self.http_indicator_count),
        ]

    def as_dict(self) -> dict[str, object]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "window_start": self.window_start,
            "window_seconds": self.window_seconds,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_dst_ports": self.unique_dst_ports,
            "unique_dst_ips": self.unique_dst_ips,
            "syn_count": self.syn_count,
            "icmp_count": self.icmp_count,
            "dns_query_count": self.dns_query_count,
            "sensitive_port_count": self.sensitive_port_count,
            "http_indicator_count": self.http_indicator_count,
        }


@dataclass(slots=True)
class _FlowAccumulator:
    src_ip: str
    dst_ip: str
    window_start: float
    window_seconds: int
    packet_count: int = 0
    byte_count: int = 0
    dst_ports: set[int] | None = None
    dst_ips: set[str] | None = None
    syn_count: int = 0
    icmp_count: int = 0
    dns_query_count: int = 0
    sensitive_port_count: int = 0
    http_indicator_count: int = 0

    def __post_init__(self) -> None:
        if self.dst_ports is None:
            self.dst_ports = set()
        if self.dst_ips is None:
            self.dst_ips = set()

    def add(self, packet: PacketRecord) -> None:
        self.packet_count += 1
        self.byte_count += max(0, int(packet.length or 0))
        if packet.dst_port is not None:
            self.dst_ports.add(packet.dst_port)
            if packet.dst_port in SENSITIVE_PORTS:
                self.sensitive_port_count += 1
        if packet.dst_ip:
            self.dst_ips.add(packet.dst_ip)
        if _is_syn(packet):
            self.syn_count += 1
        if (packet.protocol or "").upper().startswith("ICMP"):
            self.icmp_count += 1
        if packet.dns_query or (packet.protocol or "").upper() == "DNS":
            self.dns_query_count += 1
        if _has_http_indicator(packet):
            self.http_indicator_count += 1

    def feature(self) -> FlowFeature:
        return FlowFeature(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            window_start=self.window_start,
            window_seconds=self.window_seconds,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            unique_dst_ports=len(self.dst_ports or set()),
            unique_dst_ips=len(self.dst_ips or set()),
            syn_count=self.syn_count,
            icmp_count=self.icmp_count,
            dns_query_count=self.dns_query_count,
            sensitive_port_count=self.sensitive_port_count,
            http_indicator_count=self.http_indicator_count,
        )


class FlowFeatureExtractor:
    def __init__(self, time_window: int = 60) -> None:
        self.time_window = max(1, time_window)
        self._active: dict[tuple[str, str, float], _FlowAccumulator] = {}

    def extract(self, packets: list[PacketRecord]) -> list[FlowFeature]:
        accumulators: dict[tuple[str, str, float], _FlowAccumulator] = {}
        for packet in packets:
            key = self._key(packet)
            accumulator = accumulators.get(key)
            if accumulator is None:
                src_ip, dst_ip, window_start = key
                accumulator = _FlowAccumulator(src_ip, dst_ip, window_start, self.time_window)
                accumulators[key] = accumulator
            accumulator.add(packet)
        return [accumulator.feature() for accumulator in accumulators.values()]

    def observe(self, packet: PacketRecord) -> FlowFeature:
        key = self._key(packet)
        accumulator = self._active.get(key)
        if accumulator is None:
            src_ip, dst_ip, window_start = key
            accumulator = _FlowAccumulator(src_ip, dst_ip, window_start, self.time_window)
            self._active[key] = accumulator
        accumulator.add(packet)
        self._prune(self.packet_time(packet))
        return accumulator.feature()

    def reset(self) -> None:
        self._active.clear()

    def packet_time(self, packet: PacketRecord) -> float:
        if not packet.timestamp:
            return time.time()

        timestamp = packet.timestamp.strip()
        for parser in (
            datetime.fromisoformat,
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f"),
            lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        ):
            try:
                return parser(timestamp).timestamp()
            except ValueError:
                continue
        return time.time()

    def _key(self, packet: PacketRecord) -> tuple[str, str, float]:
        packet_time = self.packet_time(packet)
        window_start = packet_time - (packet_time % self.time_window)
        return (packet.src_ip or "unknown", packet.dst_ip or "unknown", window_start)

    def _prune(self, now: float) -> None:
        oldest_allowed = now - self.time_window * 3
        stale_keys = [key for key in self._active if key[2] < oldest_allowed]
        for key in stale_keys:
            self._active.pop(key, None)


def _is_syn(packet: PacketRecord) -> bool:
    flags = (packet.tcp_flags or "").upper()
    return "S" in flags and "A" not in flags


def _has_http_indicator(packet: PacketRecord) -> bool:
    if packet.http_method or packet.http_host or packet.http_path:
        return True
    protocol = (packet.protocol or "").upper()
    if protocol in {"HTTP", "HTTPS"}:
        return True
    text = packet.raw_summary.lower()
    return any(value in text for value in ("http ", "http/", "host:", "user-agent:", " get ", " post "))
