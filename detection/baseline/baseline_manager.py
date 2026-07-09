from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
import time

from models import BaselineRecord, PacketRecord
from utils.ip_utils import is_private_ip, is_public_ip


@dataclass(frozen=True, slots=True)
class PacketSample:
    timestamp: float
    timestamp_text: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    length: int
    internal_to_external: bool


@dataclass(frozen=True, slots=True)
class BaselineObservation:
    current: BaselineRecord | None
    historical_mean: BaselineRecord | None
    history_count: int


class BaselineManager:
    def __init__(self, window_seconds: int = 60, history_size: int = 30) -> None:
        self.window_seconds = max(1, window_seconds)
        self.history_size = max(1, history_size)
        self._windows: dict[str, deque[PacketSample]] = defaultdict(deque)
        self._history: dict[str, deque[BaselineRecord]] = defaultdict(lambda: deque(maxlen=self.history_size))

    def observe(self, packet: PacketRecord) -> BaselineObservation:
        if not packet.src_ip:
            return BaselineObservation(current=None, historical_mean=None, history_count=0)

        now = self.packet_time(packet)
        samples = self._windows[packet.src_ip]
        self._prune(samples, now)
        historical_samples = self._history[packet.src_ip]
        historical_mean = self._mean_record(packet.src_ip, historical_samples)

        samples.append(self._sample_from_packet(packet, now))
        current = self._record_from_samples(packet.src_ip, samples, packet.timestamp or self._format_time(now))
        historical_samples.append(current)
        return BaselineObservation(current=current, historical_mean=historical_mean, history_count=len(historical_samples) - 1)

    def update(self, packet: PacketRecord) -> BaselineRecord | None:
        return self.observe(packet).current

    def get_current_record(self, src_ip: str) -> BaselineRecord | None:
        samples = self._windows.get(src_ip)
        if not samples:
            return None
        return self._record_from_samples(src_ip, samples, samples[-1].timestamp_text)

    def all_current_records(self) -> list[BaselineRecord]:
        records: list[BaselineRecord] = []
        for src_ip, samples in self._windows.items():
            if samples:
                records.append(self._record_from_samples(src_ip, samples, samples[-1].timestamp_text))
        return records

    def reset(self) -> None:
        self._windows.clear()
        self._history.clear()

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

    def _sample_from_packet(self, packet: PacketRecord, timestamp: float) -> PacketSample:
        length = max(0, int(packet.length or 0))
        return PacketSample(
            timestamp=timestamp,
            timestamp_text=packet.timestamp or self._format_time(timestamp),
            dst_ip=packet.dst_ip or "",
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            length=length,
            internal_to_external=bool(is_private_ip(packet.src_ip) and is_public_ip(packet.dst_ip)),
        )

    def _record_from_samples(self, src_ip: str, samples: deque[PacketSample], updated_at: str) -> BaselineRecord:
        packet_count = len(samples)
        dst_ips = {sample.dst_ip for sample in samples if sample.dst_ip}
        dst_ports = {sample.dst_port for sample in samples if sample.dst_port is not None}
        connections = {
            (sample.dst_ip, sample.dst_port, sample.protocol)
            for sample in samples
            if sample.dst_ip or sample.dst_port is not None
        }
        bytes_per_window = sum(sample.length for sample in samples)
        external_count = sum(1 for sample in samples if sample.internal_to_external)
        avg_packet_length = 0.0 if packet_count == 0 else bytes_per_window / packet_count
        external_ratio = 0.0 if packet_count == 0 else external_count / packet_count
        return BaselineRecord(
            src_ip=src_ip,
            updated_at=updated_at,
            window_seconds=self.window_seconds,
            packet_count=packet_count,
            connection_count=len(connections),
            unique_dst_ips=len(dst_ips),
            unique_dst_ports=len(dst_ports),
            avg_packet_length=avg_packet_length,
            bytes_per_window=bytes_per_window,
            internal_to_external_ratio=external_ratio,
        )

    def _mean_record(self, src_ip: str, records: deque[BaselineRecord]) -> BaselineRecord | None:
        if not records:
            return None

        count = len(records)
        latest = records[-1]
        return BaselineRecord(
            src_ip=src_ip,
            updated_at=latest.updated_at,
            window_seconds=self.window_seconds,
            packet_count=round(sum(record.packet_count for record in records) / count),
            connection_count=round(sum(record.connection_count for record in records) / count),
            unique_dst_ips=round(sum(record.unique_dst_ips for record in records) / count),
            unique_dst_ports=round(sum(record.unique_dst_ports for record in records) / count),
            avg_packet_length=sum(record.avg_packet_length for record in records) / count,
            bytes_per_window=round(sum(record.bytes_per_window for record in records) / count),
            internal_to_external_ratio=sum(record.internal_to_external_ratio for record in records) / count,
        )

    def _prune(self, samples: deque[PacketSample], now: float) -> None:
        while samples and now - samples[0].timestamp > self.window_seconds:
            samples.popleft()

    def _format_time(self, timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp).isoformat(sep=" ", timespec="milliseconds")
