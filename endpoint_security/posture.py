from __future__ import annotations

import csv
import io
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SecurityCheck:
    identifier: str
    title: str
    state: str
    value: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class EndpointPostureService:
    """Collect lightweight, read-only Windows posture information."""

    def __init__(self, is_windows: bool | None = None) -> None:
        self.is_windows = os.name == "nt" if is_windows is None else is_windows

    def collect(self) -> list[dict[str, str]]:
        if not self.is_windows:
            return [
                SecurityCheck(
                    "platform", "Windows endpoint posture", "unavailable", "Unsupported platform",
                    "Firewall, Defender, UAC, and BitLocker checks run only on Windows.",
                    "Run the local analyst service on a supported Windows endpoint.",
                ).to_dict()
            ]
        return [self._firewall(), self._defender(), self._uac(), self._bitlocker()]

    def _firewall(self) -> dict[str, str]:
        try:
            profiles = _as_list(self._powershell_json("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"))
            disabled = [str(profile.get("Name", "Unknown")) for profile in profiles if not _as_bool(profile.get("Enabled"))]
            if disabled:
                return SecurityCheck("firewall", "Windows Firewall", "fail", "Profiles disabled", f"Disabled profiles: {', '.join(disabled)}.", "Enable all active Windows Firewall profiles and review policy exceptions.").to_dict()
            return SecurityCheck("firewall", "Windows Firewall", "pass", "All profiles enabled", "Domain, private, and public profile data was read successfully.", "Keep profile policies centrally managed.").to_dict()
        except RuntimeError as exc:
            return _unavailable("firewall", "Windows Firewall", exc)

    def _defender(self) -> dict[str, str]:
        try:
            status = self._powershell_json("Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, NISEnabled | ConvertTo-Json -Compress")
            realtime = _as_bool(status.get("RealTimeProtectionEnabled"))
            antivirus = _as_bool(status.get("AntivirusEnabled"))
            service = _as_bool(status.get("AMServiceEnabled"))
            network_inspection = _as_bool(status.get("NISEnabled"))
            if service and antivirus and realtime and network_inspection:
                return SecurityCheck("defender", "Microsoft Defender", "pass", "Realtime protection enabled", "Antivirus, service, realtime protection, and network inspection are enabled.", "Keep definitions and platform updates current.").to_dict()
            state = "fail" if not service or not antivirus or not realtime else "warning"
            missing = [name for name, enabled in {"service": service, "antivirus": antivirus, "realtime protection": realtime, "network inspection": network_inspection}.items() if not enabled]
            return SecurityCheck("defender", "Microsoft Defender", state, "Protection needs attention", f"Disabled or unavailable: {', '.join(missing)}.", "Investigate the approved endpoint-security policy before enabling protection.").to_dict()
        except RuntimeError as exc:
            return _unavailable("defender", "Microsoft Defender", exc)

    def _uac(self) -> dict[str, str]:
        try:
            status = self._powershell_json("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA | Select-Object EnableLUA | ConvertTo-Json -Compress")
            enabled = int(status.get("EnableLUA", 0)) == 1
            if enabled:
                return SecurityCheck("uac", "User Account Control", "pass", "Enabled", "EnableLUA is enabled in the local system policy.", "Keep UAC enabled and use standard accounts for routine work.").to_dict()
            return SecurityCheck("uac", "User Account Control", "warning", "Disabled", "EnableLUA is disabled in the local system policy.", "Review the impact of enabling UAC with the system administrator.").to_dict()
        except (RuntimeError, TypeError, ValueError) as exc:
            return _unavailable("uac", "User Account Control", exc)

    def _bitlocker(self) -> dict[str, str]:
        try:
            status = self._powershell_json("Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object VolumeStatus, ProtectionStatus | ConvertTo-Json -Compress")
            protected = str(status.get("ProtectionStatus", "")).lower() == "on"
            encrypted = str(status.get("VolumeStatus", "")).lower() == "fullyencrypted"
            if protected and encrypted:
                return SecurityCheck("bitlocker", "BitLocker", "pass", "System drive protected", "System drive encryption and protection are enabled.", "Escrow recovery keys according to the approved policy.").to_dict()
            return SecurityCheck("bitlocker", "BitLocker", "warning", "Protection incomplete", f"Volume status: {status.get('VolumeStatus', 'unknown')}; protection: {status.get('ProtectionStatus', 'unknown')}.", "Review system-drive encryption requirements with the device owner.").to_dict()
        except RuntimeError as exc:
            return _unavailable("bitlocker", "BitLocker", exc)

    def _powershell_json(self, command: str) -> dict[str, Any] | list[dict[str, Any]]:
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"PowerShell is unavailable: {exc}") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "PowerShell command failed."
            raise RuntimeError(message)
        try:
            payload = json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError("PowerShell did not return valid JSON.") from exc
        if not isinstance(payload, (dict, list)):
            raise RuntimeError("PowerShell returned an unexpected value.")
        return payload


class ProcessInventoryService:
    """Read a bounded process inventory without altering endpoint state."""

    def __init__(self, is_windows: bool | None = None) -> None:
        self.is_windows = os.name == "nt" if is_windows is None else is_windows

    def list_processes(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        return self._windows_processes(limit) if self.is_windows else self._portable_processes(limit)

    def _windows_processes(self, limit: int) -> list[dict[str, Any]]:
        try:
            completed = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Could not read the Windows process list: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "Could not read the Windows process list.")
        records = []
        for row in csv.reader(io.StringIO(completed.stdout)):
            if len(row) < 2:
                continue
            try:
                pid = int(row[1])
            except ValueError:
                continue
            records.append({"pid": pid, "name": row[0], "memory": row[4] if len(row) > 4 else "", "path": ""})
            if len(records) >= limit:
                break
        return records

    def _portable_processes(self, limit: int) -> list[dict[str, Any]]:
        try:
            completed = subprocess.run(["ps", "-eo", "pid=,comm="], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if completed.returncode != 0:
            return []
        records = []
        for line in completed.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            records.append({"pid": int(parts[0]), "name": parts[1], "memory": "", "path": ""})
            if len(records) >= limit:
                break
        return records


def _as_list(value: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    return value if isinstance(value, list) else [value]


def _as_bool(value: object) -> bool:
    return value is True or str(value).strip().lower() == "true"


def _unavailable(identifier: str, title: str, exc: Exception) -> dict[str, str]:
    return SecurityCheck(identifier, title, "unavailable", "Unavailable", str(exc), "Verify Windows support and local administrator policy permissions.").to_dict()
