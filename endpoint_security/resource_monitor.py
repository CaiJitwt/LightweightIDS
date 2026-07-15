from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import socket
from threading import Event, Lock, Thread
from time import monotonic
from typing import Any, Callable

from models import AlertRecord, RuleRecord
from storage.database import Database
from storage.repositories import AlertRepository, RuleRepository


RESOURCE_RULES = {
    "SUSTAINED_CPU_LOAD": ("cpuPercent", "CPU"),
    "SUSTAINED_GPU_LOAD": ("gpuPercent", "GPU"),
}


@dataclass
class _PressureState:
    above_since: float | None = None
    alerted: bool = False


class ResourceThreatMonitorService:
    """Detect sustained endpoint load as a review signal, not proof of malware."""

    def __init__(
        self,
        database: Database,
        sample_provider: Callable[[], dict[str, Any]],
        poll_seconds: float = 5.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.rules = RuleRepository(database)
        self.alerts = AlertRepository(database)
        self.sample_provider = sample_provider
        self.poll_seconds = max(1.0, poll_seconds)
        self.clock = clock
        self._states = {rule_id: _PressureState() for rule_id in RESOURCE_RULES}
        self._lock = Lock()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._last_sample: dict[str, Any] = {}
        self._last_error = ""
        self._alerts_added = 0

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(target=self._run, name="endpoint-resource-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3.0)
        with self._lock:
            self._thread = None

    def shutdown(self) -> None:
        self.stop()

    def reset_statistics(self) -> None:
        with self._lock:
            self._states = {rule_id: _PressureState() for rule_id in RESOURCE_RULES}
            self._last_sample = {}
            self._last_error = ""
            self._alerts_added = 0

    def poll_once(self, sample: dict[str, Any] | None = None, now: float | None = None) -> list[AlertRecord]:
        current = dict(sample if sample is not None else self.sample_provider())
        observed_at = self.clock() if now is None else now
        configured = {rule.id: rule for rule in self.rules.list_all() if rule.id in RESOURCE_RULES}
        generated: list[AlertRecord] = []
        with self._lock:
            self._last_sample = current
            self._last_error = ""
            for rule_id, (sample_key, label) in RESOURCE_RULES.items():
                alert = self._evaluate(rule_id, configured.get(rule_id), sample_key, label, current, observed_at)
                if alert is not None:
                    self.alerts.add(alert)
                    generated.append(alert)
                    self._alerts_added += 1
        return generated

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": "running" if self._thread and self._thread.is_alive() else "stopped",
                "lastSample": dict(self._last_sample),
                "lastError": self._last_error,
                "alertsAdded": self._alerts_added,
            }

    def _evaluate(
        self,
        rule_id: str,
        rule: RuleRecord | None,
        sample_key: str,
        label: str,
        sample: dict[str, Any],
        now: float,
    ) -> AlertRecord | None:
        state = self._states[rule_id]
        value = sample.get(sample_key)
        if rule is None or not rule.enabled or not isinstance(value, (int, float)):
            state.above_since = None
            state.alerted = False
            return None
        threshold = max(1.0, min(100.0, float(rule.threshold)))
        if float(value) < threshold:
            state.above_since = None
            state.alerted = False
            return None
        if state.above_since is None:
            state.above_since = now
            return None
        sustained_seconds = now - state.above_since
        if state.alerted or sustained_seconds < max(1, rule.time_window):
            return None
        state.alerted = True
        hostname = socket.gethostname()
        return AlertRecord(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            rule_id=rule.id,
            rule_name=rule.name,
            alert_type=rule.id,
            severity=rule.severity,
            src_ip="127.0.0.1",
            protocol="HOST",
            description=(
                f"{label} utilization remained above the configured threshold. This can indicate cryptomining, "
                "malware, or a legitimate intensive workload and requires process-level validation."
            ),
            evidence=(
                f"hostname={hostname}; metric={sample_key}; utilization={float(value):.1f}; "
                f"threshold={threshold:.1f}; sustained_seconds={int(sustained_seconds)}"
            ),
        )

    def _run(self) -> None:
        while not self._stop_event.wait(self.poll_seconds):
            try:
                self.poll_once()
            except Exception as exc:
                with self._lock:
                    self._last_error = str(exc)
