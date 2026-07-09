from __future__ import annotations

import math

from detection.rule_base import RuleBase
from detection.window_counter import WindowCounter
from models import AlertRecord, PacketRecord


class DnsAnomalyRule(RuleBase):
    rule_id = "DNS_ANOMALY"
    name = "DNS anomaly detection"
    category = "dns"
    severity = "MEDIUM"
    threshold = 40
    time_window = 60
    long_domain_length = 52
    entropy_threshold = 3.8

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._counter = WindowCounter(self.time_window)

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if packet.protocol != "DNS" and not packet.dns_query:
            return []

        alerts: list[AlertRecord] = []
        query = (packet.dns_query or "").strip(".")
        now = self.packet_time(packet)

        if packet.src_ip:
            count = self._counter.add((packet.src_ip,), now)
            if count >= self.threshold:
                alerts.append(
                    self.create_alert(
                        packet,
                        alert_type="DNS_QUERY_FREQUENCY",
                        description="Detected high-frequency DNS queries in a short time window.",
                        evidence=f"src_ip={packet.src_ip}; count={count}; time_window={self.time_window}s",
                    )
                )

        if query and len(query) >= self.long_domain_length:
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="DNS_TUNNELING_SUSPECTED",
                    description="Detected an unusually long DNS query, which may indicate DNS tunneling.",
                    evidence=f"dns_query={query}; length={len(query)}",
                )
            )

        if self._looks_like_dga(query):
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type="DGA_DOMAIN_SUSPECTED",
                    description="Detected a high-entropy random-looking domain, which may indicate DGA activity.",
                    evidence=f"dns_query={query}; entropy={self._entropy(query):.2f}",
                )
            )

        return alerts

    def reset(self) -> None:
        self._counter = WindowCounter(self.time_window)

    def set_time_window(self, time_window: int) -> None:
        super().set_time_window(time_window)
        self._counter = WindowCounter(self.time_window)

    def _looks_like_dga(self, query: str) -> bool:
        if not query or "." not in query:
            return False
        label = query.split(".", 1)[0]
        if len(label) < 12:
            return False
        digit_count = sum(char.isdigit() for char in label)
        return self._entropy(label) >= self.entropy_threshold and digit_count >= 2

    def _entropy(self, value: str) -> float:
        if not value:
            return 0.0
        frequencies = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in frequencies.values())
