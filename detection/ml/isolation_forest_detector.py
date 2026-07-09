from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
import pickle
from statistics import mean
from typing import Any

from detection.features import FlowFeature
from detection.ml.simple_anomaly import SimpleAnomalyDetector


DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "models" / "flow_anomaly.pkl"


@dataclass(frozen=True, slots=True)
class FlowAnomalyResult:
    score: float
    reasons: list[str]
    backend: str


@dataclass
class IsolationForestFlowDetector:
    model_path: Path = DEFAULT_MODEL_PATH
    min_train_samples: int = 8
    history_size: int = 100
    contamination: float = 0.1
    use_sklearn: bool = True
    _history: deque[FlowFeature] = field(default_factory=deque)
    _model: Any = None
    _sklearn_available: bool = False
    _fallback: SimpleAnomalyDetector = field(default_factory=SimpleAnomalyDetector)

    def __post_init__(self) -> None:
        self.model_path = Path(self.model_path)
        if self.use_sklearn:
            try:
                from sklearn.ensemble import IsolationForest  # noqa: F401

                self._sklearn_available = True
            except Exception:
                self._sklearn_available = False

    @property
    def backend(self) -> str:
        if self._sklearn_available and self._model is not None:
            return "sklearn_isolation_forest"
        return "simple_fallback"

    def train(self, features: list[FlowFeature]) -> None:
        self._history.clear()
        for feature in features[-self.history_size :]:
            self._history.append(feature)
        if self._sklearn_available and len(features) >= self.min_train_samples:
            from sklearn.ensemble import IsolationForest

            self._model = IsolationForest(contamination=self.contamination, random_state=42)
            self._model.fit([feature.vector() for feature in features])

    def score_feature(self, feature: FlowFeature, *, update: bool = True) -> FlowAnomalyResult:
        if self._sklearn_available and self._model is None and len(self._history) >= self.min_train_samples:
            self.train(list(self._history))

        heuristic_score, reasons = self._heuristic_score(feature)
        model_score = 0.0
        if self._sklearn_available and self._model is not None:
            decision = float(self._model.decision_function([feature.vector()])[0])
            model_score = max(0.0, min(100.0, 50.0 - decision * 100.0))
            if model_score >= 60:
                reasons.append(f"isolation_forest_score={model_score:.1f}")

        score = max(heuristic_score, model_score)
        if update:
            self._remember(feature)
        return FlowAnomalyResult(score=min(score, 100.0), reasons=reasons[:5], backend=self.backend)

    def save(self, path: str | Path | None = None) -> None:
        target = Path(path) if path is not None else self.model_path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "history": list(self._history),
            "model": self._model,
            "sklearn_available": self._sklearn_available,
            "min_train_samples": self.min_train_samples,
            "history_size": self.history_size,
            "contamination": self.contamination,
        }
        with target.open("wb") as file:
            pickle.dump(payload, file)

    def load(self, path: str | Path | None = None) -> bool:
        target = Path(path) if path is not None else self.model_path
        if not target.exists():
            return False
        with target.open("rb") as file:
            payload = pickle.load(file)
        self._history = deque(payload.get("history", []), maxlen=self.history_size)
        self._model = payload.get("model")
        self.min_train_samples = int(payload.get("min_train_samples", self.min_train_samples))
        self.history_size = int(payload.get("history_size", self.history_size))
        self.contamination = float(payload.get("contamination", self.contamination))
        return True

    def reset(self) -> None:
        self._history.clear()
        self._model = None
        self._fallback.reset()

    def _remember(self, feature: FlowFeature) -> None:
        self._history.append(feature)
        while len(self._history) > self.history_size:
            self._history.popleft()

    def _heuristic_score(self, feature: FlowFeature) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        baseline = self._baseline()
        if baseline:
            checks = [
                ("packet_count", feature.packet_count, baseline["packet_count"], 8, 25),
                ("byte_count", feature.byte_count, baseline["byte_count"], 4000, 25),
                ("unique_dst_ports", feature.unique_dst_ports, baseline["unique_dst_ports"], 4, 30),
                ("unique_dst_ips", feature.unique_dst_ips, baseline["unique_dst_ips"], 4, 25),
                ("syn_count", feature.syn_count, baseline["syn_count"], 8, 20),
                ("dns_query_count", feature.dns_query_count, baseline["dns_query_count"], 8, 18),
                ("sensitive_port_count", feature.sensitive_port_count, baseline["sensitive_port_count"], 2, 25),
                ("http_indicator_count", feature.http_indicator_count, baseline["http_indicator_count"], 6, 15),
            ]
            for label, current, expected, minimum_delta, weight in checks:
                if expected <= 0:
                    continue
                if current >= max(expected * 3, expected + minimum_delta):
                    score += weight
                    reasons.append(f"{label}_spike={current}/baseline={expected:.1f}")

        absolute_checks = [
            (feature.unique_dst_ports >= 8, 45, f"many_dst_ports={feature.unique_dst_ports}"),
            (feature.unique_dst_ips >= 10, 30, f"many_dst_ips={feature.unique_dst_ips}"),
            (feature.sensitive_port_count >= 3, 30, f"sensitive_port_count={feature.sensitive_port_count}"),
            (feature.syn_count >= 8, 30, f"syn_count={feature.syn_count}"),
            (feature.icmp_count >= 20, 20, f"icmp_count={feature.icmp_count}"),
            (feature.dns_query_count >= 20, 20, f"dns_query_count={feature.dns_query_count}"),
            (feature.byte_count >= 15000, 25, f"byte_count={feature.byte_count}"),
            (feature.http_indicator_count >= 20, 15, f"http_indicator_count={feature.http_indicator_count}"),
        ]
        for condition, weight, reason in absolute_checks:
            if condition:
                score += weight
                reasons.append(reason)

        return min(score, 100.0), reasons

    def _baseline(self) -> dict[str, float]:
        if len(self._history) < self.min_train_samples:
            return {}

        return {
            "packet_count": mean(feature.packet_count for feature in self._history),
            "byte_count": mean(feature.byte_count for feature in self._history),
            "unique_dst_ports": mean(feature.unique_dst_ports for feature in self._history),
            "unique_dst_ips": mean(feature.unique_dst_ips for feature in self._history),
            "syn_count": mean(feature.syn_count for feature in self._history),
            "icmp_count": mean(feature.icmp_count for feature in self._history),
            "dns_query_count": mean(feature.dns_query_count for feature in self._history),
            "sensitive_port_count": mean(feature.sensitive_port_count for feature in self._history),
            "http_indicator_count": mean(feature.http_indicator_count for feature in self._history),
        }
