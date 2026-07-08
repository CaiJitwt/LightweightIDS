from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class WindowCounter:
    time_window: float
    buckets: dict[tuple[object, ...], deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def add(self, key: tuple[object, ...], timestamp: float) -> int:
        values = self.buckets[key]
        values.append(timestamp)
        self._prune(values, timestamp)
        return len(values)

    def count(self, key: tuple[object, ...], timestamp: float) -> int:
        values = self.buckets[key]
        self._prune(values, timestamp)
        return len(values)

    def reset(self) -> None:
        self.buckets.clear()

    def _prune(self, values: deque[float], now: float) -> None:
        while values and now - values[0] > self.time_window:
            values.popleft()
