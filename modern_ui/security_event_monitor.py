from __future__ import annotations

from datetime import datetime, timezone
from threading import Event, Lock, Thread
from typing import Any

from detection.analysis.security_event import SecurityEventAnalyzer
from endpoint_security import WindowsEventCollector
from storage.database import Database
from storage.repositories import RuleRepository, SecurityEventRepository


class SecurityEventMonitorService:
    """Background Windows Event Log collection with bounded SQLite persistence."""

    def __init__(
        self,
        database: Database,
        collector: WindowsEventCollector | None = None,
        poll_seconds: int = 5,
    ) -> None:
        self.database = database
        self.collector = collector or WindowsEventCollector()
        self.repository = SecurityEventRepository(database)
        self.rules = RuleRepository(database)
        self.analyzer = SecurityEventAnalyzer(self.rules.list_all())
        self._poll_seconds = max(2, min(poll_seconds, 300))
        self._state = "stopped"
        self._last_poll = ""
        self._last_error = ""
        self._unavailable_channels: list[str] = []
        self._session_events = 0
        self._session_alerts = 0
        self._state_lock = Lock()
        self._poll_lock = Lock()
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> dict[str, Any]:
        if not self.collector.is_windows:
            raise RuntimeError("Windows security-event monitoring is available only on Windows.")
        with self._state_lock:
            already_running = bool(self._thread and self._thread.is_alive())
            if not already_running:
                self._state = "running"
                self._last_error = ""
                self._stop_event.clear()
                self._thread = Thread(target=self._run, name="security-event-monitor", daemon=True)
                self._thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._state_lock:
            thread = self._thread
            self._stop_event.set()
        if thread and thread.is_alive():
            thread.join(timeout=max(3.0, self._poll_seconds + 1.0))
        with self._state_lock:
            self._thread = None
            self._state = "stopped"
        return self.status()

    def shutdown(self) -> None:
        self.stop()

    def set_poll_seconds(self, seconds: int) -> None:
        self._poll_seconds = max(2, min(seconds, 300))

    def reset_statistics(self) -> None:
        with self._poll_lock:
            self.analyzer.reset()
            with self._state_lock:
                self._last_poll = ""
                self._last_error = ""
                self._unavailable_channels = []
                self._session_events = 0
                self._session_alerts = 0

    def refresh_once(self) -> dict[str, Any]:
        with self._poll_lock:
            result = self.collector.collect(self.repository.cursors())
            inserted = self.repository.add_many(result.records)
            latest_by_channel: dict[str, int] = {}
            for event in result.records:
                latest_by_channel[event.channel] = max(latest_by_channel.get(event.channel, 0), event.record_id)
            for channel, record_id in latest_by_channel.items():
                self.repository.update_cursor(channel, record_id)

            self.analyzer.update_rules(self.rules.list_all())
            alerts_added = 0
            for event in inserted:
                if event.id is None:
                    continue
                for alert in self.analyzer.process(event):
                    self.repository.add_alert(event.id, alert)
                    alerts_added += 1

            with self._state_lock:
                self._last_poll = _utc_now()
                self._unavailable_channels = result.unavailable_channels
                self._last_error = "; ".join(result.errors)
                self._session_events += len(inserted)
                self._session_alerts += alerts_added
            return {
                **self.status(),
                "eventsAdded": len(inserted),
                "alertsAdded": alerts_added,
            }

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            state = self._state
            last_poll = self._last_poll
            last_error = self._last_error
            unavailable = list(self._unavailable_channels)
            session_events = self._session_events
            session_alerts = self._session_alerts
        return {
            "state": state,
            "platformAvailable": self.collector.is_windows,
            "pollSeconds": self._poll_seconds,
            "lastPoll": last_poll,
            "lastError": last_error,
            "monitoredChannels": list(self.collector_channels),
            "unavailableChannels": unavailable,
            "eventTotal": self.repository.count(),
            "severityCounts": self.repository.count_by_severity(),
            "sessionEvents": session_events,
            "sessionAlerts": session_alerts,
        }

    @property
    def collector_channels(self) -> tuple[str, ...]:
        from endpoint_security.event_log import CHANNEL_EVENT_IDS

        return tuple(CHANNEL_EVENT_IDS)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.refresh_once()
            except Exception as exc:
                with self._state_lock:
                    self._last_poll = _utc_now()
                    self._last_error = str(exc)
            if self._stop_event.wait(self._poll_seconds):
                break


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
