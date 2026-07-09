from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import mean

from models import PacketRecord


@dataclass(frozen=True)
class AnomalyResult:
    score: float
    reasons: list[str]


@dataclass
class SimpleAnomalyDetector:
    history_size: int = 50
    _length_history: dict[str, deque[int]] = field(default_factory=lambda: defaultdict(deque))
    _seen_ports: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))

    RISKY_PORTS = {1337, 31337, 4444, 5555, 6666, 6667, 7777, 9001}
    COMMON_PROTOCOLS = {
        "ARP",
        "DHCP",
        "DNS",
        "HTTP",
        "HTTPS",
        "ICMP",
        "ICMPv6",
        "LLMNR",
        "MDNS",
        "NBNS",
        "NTP",
        "QUIC",
        "TCP",
        "TLS",
        "UDP",
    }

    def score_packet(self, packet: PacketRecord) -> AnomalyResult:
        score = 0.0
        reasons: list[str] = []

        protocol = (packet.protocol or "UNKNOWN").upper()
        if protocol not in self.COMMON_PROTOCOLS:
            score += 30
            reasons.append(f"uncommon_protocol={packet.protocol}")

        if packet.dst_port in self.RISKY_PORTS:
            score += 35
            reasons.append(f"risky_port={packet.dst_port}")
        elif packet.dst_port and packet.dst_port >= 49152:
            score += 18
            reasons.append(f"high_ephemeral_dst_port={packet.dst_port}")

        if packet.length >= 9000:
            score += 40
            reasons.append(f"very_large_packet={packet.length}")
        elif packet.length >= 3000:
            score += 20
            reasons.append(f"large_packet={packet.length}")

        if packet.src_ip:
            history = self._length_history[packet.src_ip]
            if len(history) >= 5:
                baseline = mean(history)
                if baseline > 0 and packet.length > baseline * 4:
                    score += 25
                    reasons.append(f"length_spike={packet.length}/baseline={baseline:.1f}")
            history.append(packet.length)
            while len(history) > self.history_size:
                history.popleft()

            if packet.dst_port is not None:
                seen_ports = self._seen_ports[packet.src_ip]
                if seen_ports and packet.dst_port not in seen_ports and len(seen_ports) >= 8:
                    score += 15
                    reasons.append(f"new_port_after_profile={packet.dst_port}")
                seen_ports.add(packet.dst_port)

        return AnomalyResult(score=min(score, 100.0), reasons=reasons)

    def score(self, features: dict[str, object]) -> float:
        packet = PacketRecord(
            src_ip=str(features.get("src_ip") or "") or None,
            dst_ip=str(features.get("dst_ip") or "") or None,
            dst_port=self._optional_int(features.get("dst_port")),
            protocol=str(features.get("protocol") or "UNKNOWN"),
            length=self._optional_int(features.get("length")) or 0,
        )
        return self.score_packet(packet).score

    def reset(self) -> None:
        self._length_history.clear()
        self._seen_ports.clear()

    def _optional_int(self, value: object) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
