from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import subprocess
from typing import Any

from models import SecurityEventRecord


CHANNEL_EVENT_IDS: dict[str, tuple[int, ...]] = {
    "Security": (1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4728, 4732),
    "System": (7045,),
    "Microsoft-Windows-PowerShell/Operational": (4103, 4104),
    "Microsoft-Windows-Windows Defender/Operational": (1116, 1117, 5001),
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": (21, 24, 25),
}


@dataclass(slots=True)
class EventCollectionResult:
    records: list[SecurityEventRecord] = field(default_factory=list)
    unavailable_channels: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class WindowsEventCollector:
    """Read a bounded, incremental subset of Windows Event Log channels."""

    def __init__(self, is_windows: bool | None = None, initial_lookback_seconds: int = 900) -> None:
        self.is_windows = os.name == "nt" if is_windows is None else is_windows
        self.initial_lookback_seconds = max(60, min(initial_lookback_seconds, 86_400))

    def collect(self, cursors: dict[str, int], limit_per_channel: int = 200) -> EventCollectionResult:
        result = EventCollectionResult()
        if not self.is_windows:
            result.unavailable_channels.extend(CHANNEL_EVENT_IDS)
            result.errors.append("Windows Event Log collection is available only on Windows.")
            return result

        limit = max(1, min(limit_per_channel, 1_000))
        for channel, event_ids in CHANNEL_EVENT_IDS.items():
            try:
                raw_events = self._read_channel(channel, event_ids, cursors.get(channel, 0), limit)
                result.records.extend(self.normalize(raw, channel) for raw in raw_events)
            except RuntimeError as exc:
                result.unavailable_channels.append(channel)
                result.errors.append(f"{channel}: {exc}")
        result.records.sort(key=lambda event: (event.timestamp, event.channel, event.record_id))
        return result

    def _read_channel(self, channel: str, event_ids: tuple[int, ...], cursor: int, limit: int) -> list[dict[str, Any]]:
        event_clause = " or ".join(f"EventID={event_id}" for event_id in event_ids)
        if cursor > 0:
            time_or_cursor = f"(EventRecordID > {cursor})"
        else:
            milliseconds = self.initial_lookback_seconds * 1_000
            time_or_cursor = f"TimeCreated[timediff(@SystemTime) <= {milliseconds}]"
        xpath = f"*[System[({event_clause}) and {time_or_cursor}]]"
        script = (
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "$ErrorActionPreference='Stop';"
            "try{"
            f"$events=@(Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' -MaxEvents {limit} -Oldest -ErrorAction Stop)"
            "}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$events=@()}else{throw}};"
            "$items=@($events | ForEach-Object {"
            "$xml=[xml]$_.ToXml();$data=@{};"
            "foreach($node in @($xml.Event.EventData.Data)){"
            "$name=[string]$node.Name;$value=[string]$node.'#text';"
            "if(-not $value){$value=[string]$node.InnerText};"
            "if($name){$data[$name]=$value}};"
            "[pscustomobject]@{Channel=$_.LogName;EventId=$_.Id;RecordId=$_.RecordId;"
            "TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Provider=$_.ProviderName;"
            "Computer=$_.MachineName;Level=$_.LevelDisplayName;Message=[string]$_.Message;Data=$data}});"
            "ConvertTo-Json -InputObject $items -Compress -Depth 6"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"could not query the channel: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "Get-WinEvent returned an error.")
        output = completed.stdout.strip()
        if not output:
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError("PowerShell returned invalid event JSON.") from exc
        if payload is None:
            return []
        if isinstance(payload, dict):
            return [payload]
        if not isinstance(payload, list):
            raise RuntimeError("PowerShell returned an unexpected event payload.")
        return [item for item in payload if isinstance(item, dict)]

    @staticmethod
    def normalize(raw: dict[str, Any], fallback_channel: str = "") -> SecurityEventRecord:
        details_value = raw.get("Data")
        details = {
            str(key): _bounded_text(value, 2_000)
            for key, value in (details_value.items() if isinstance(details_value, dict) else [])
            if key and value is not None
        }
        event_id = _integer(raw.get("EventId"))
        source_ip = _first(details, "IpAddress", "SourceNetworkAddress", "ClientAddress")
        if source_ip in {"-", "::1", "127.0.0.1", "::ffff:127.0.0.1"}:
            source_ip = ""
        message = _bounded_text(raw.get("Message"), 500)
        provider = _bounded_text(raw.get("Provider"), 160)
        timestamp = _normalize_timestamp(raw.get("TimeCreated"))
        return SecurityEventRecord(
            timestamp=timestamp,
            channel=_bounded_text(raw.get("Channel") or fallback_channel, 200),
            event_id=event_id,
            record_id=_integer(raw.get("RecordId")),
            provider=provider,
            computer=_bounded_text(raw.get("Computer"), 255),
            level=_bounded_text(raw.get("Level"), 80),
            user=_first(details, "TargetUserName", "SubjectUserName", "User", "AccountName"),
            source_ip=source_ip,
            logon_type=_first(details, "LogonType"),
            process_name=_first(details, "NewProcessName", "ProcessName", "ApplicationName"),
            command_line=_bounded_text(
                _first(details, "CommandLine", "ScriptBlockText", "HostApplication", "Payload"),
                2_000,
            ),
            summary=message or f"Windows event {event_id} from {provider or 'unknown provider'}.",
            details=details,
            severity=_event_severity(event_id),
        )


def _first(values: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = values.get(key, "").strip()
        if value and value != "-":
            return value
    return ""


def _bounded_text(value: object, limit: int) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _normalize_timestamp(value: object) -> str:
    text = str(value or "").strip()
    if text:
        return text.replace("Z", "+00:00")
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _event_severity(event_id: int) -> str:
    if event_id in {1102, 5001}:
        return "CRITICAL"
    if event_id in {4697, 4698, 4702, 4720, 4728, 4732, 7045, 1116}:
        return "HIGH"
    if event_id in {4625, 4648, 4672, 4103, 4104, 21, 24, 25}:
        return "MEDIUM"
    return "LOW"
