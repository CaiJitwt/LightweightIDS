from __future__ import annotations

from endpoint_security.resource_monitor import ResourceThreatMonitorService
from models import RuleRecord
from storage.database import Database
from storage.repositories import AlertRepository, RuleRepository


def _tune_rule(database: Database, rule_id: str, *, threshold: int = 80, window: int = 10) -> None:
    repository = RuleRepository(database)
    current = next(rule for rule in repository.list_all() if rule.id == rule_id)
    repository.update_rule(
        RuleRecord(
            id=current.id,
            name=current.name,
            category=current.category,
            severity=current.severity,
            enabled=True,
            threshold=threshold,
            time_window=window,
            description=current.description,
        )
    )


def test_sustained_cpu_load_alerts_only_after_full_window_and_once(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    _tune_rule(database, "SUSTAINED_CPU_LOAD")
    monitor = ResourceThreatMonitorService(database, lambda: {})

    assert monitor.poll_once({"cpuPercent": 95.0, "gpuPercent": None}, now=0) == []
    assert monitor.poll_once({"cpuPercent": 96.0, "gpuPercent": None}, now=9) == []
    alerts = monitor.poll_once({"cpuPercent": 97.0, "gpuPercent": None}, now=10)
    assert [alert.rule_id for alert in alerts] == ["SUSTAINED_CPU_LOAD"]
    assert "not proof" not in alerts[0].description.lower()
    assert "legitimate intensive workload" in alerts[0].description
    assert monitor.poll_once({"cpuPercent": 98.0, "gpuPercent": None}, now=30) == []
    assert AlertRepository(database).count() == 1


def test_gpu_load_requires_available_telemetry_and_resets_after_recovery(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    _tune_rule(database, "SUSTAINED_GPU_LOAD", threshold=85, window=5)
    monitor = ResourceThreatMonitorService(database, lambda: {})

    assert monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": None}, now=0) == []
    assert monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": 92.0}, now=1) == []
    assert [alert.rule_id for alert in monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": 93.0}, now=6)] == ["SUSTAINED_GPU_LOAD"]
    assert monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": 20.0}, now=7) == []
    assert monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": 94.0}, now=8) == []
    assert [alert.rule_id for alert in monitor.poll_once({"cpuPercent": 0.0, "gpuPercent": 95.0}, now=13)] == ["SUSTAINED_GPU_LOAD"]
