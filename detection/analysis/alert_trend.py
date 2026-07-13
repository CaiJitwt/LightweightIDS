from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev


@dataclass(frozen=True)
class AlertTrendPoint:
    bucket: str
    count: int
    is_spike: bool = False
    threshold: float = 0.0


class AlertTrendAnalyzer:
    def analyze(self, bucket_counts: list[tuple[str, int]]) -> list[AlertTrendPoint]:
        points: list[AlertTrendPoint] = []
        history: list[int] = []

        for bucket, count in bucket_counts:
            threshold = self._threshold(history)
            is_spike = bool(history and count > threshold)
            points.append(AlertTrendPoint(bucket=bucket, count=count, is_spike=is_spike, threshold=threshold))
            history.append(count)

        return points

    def _threshold(self, history: list[int]) -> float:
        if not history:
            return 0.0
        return mean(history) + 2 * pstdev(history)
