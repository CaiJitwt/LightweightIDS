from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
import re
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
        checks = (self._firewall, self._defender, self._uac, self._bitlocker)
        with ThreadPoolExecutor(max_workers=len(checks), thread_name_prefix="endpoint-posture") as executor:
            futures = [executor.submit(check) for check in checks]
            return [future.result() for future in futures]

    def _firewall(self) -> dict[str, str]:
        try:
            profile_keys = (
                ("Domain", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
                ("Private", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
                ("Public", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"),
            )
            disabled = [
                name
                for name, path in profile_keys
                if self._registry_dword(path, "EnableFirewall") != 1
            ]
            if disabled:
                return SecurityCheck("firewall", "Windows Firewall", "fail", "Profiles disabled", f"Disabled profiles: {', '.join(disabled)}.", "Enable all active Windows Firewall profiles and review policy exceptions.").to_dict()
            return SecurityCheck("firewall", "Windows Firewall", "pass", "All profiles enabled", "Domain, private, and public firewall policy values are enabled.", "Keep profile policies centrally managed.").to_dict()
        except RuntimeError as exc:
            return _unavailable("firewall", "Windows Firewall", exc)

    def _defender(self) -> dict[str, str]:
        service_running = self._service_running("WinDefend")
        network_service_running = self._service_running("WdNisSvc")
        if service_running is False:
            network_detail = (
                "The network inspection service is also stopped."
                if network_service_running is False
                else "The network inspection service state could not be confirmed."
            )
            return SecurityCheck(
                "defender",
                "Microsoft Defender",
                "warning",
                "Inactive or externally managed",
                f"The Microsoft Defender antivirus service is stopped. {network_detail}",
                "Confirm that another approved antivirus product is active, or review the Defender service policy.",
            ).to_dict()

        commands = (
            (
                "$status = Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' "
                "-ClassName MSFT_MpComputerStatus -OperationTimeoutSec 10; "
                "if ($null -eq $status) { $result = [pscustomobject]@{Available=$false} } "
                "else { $result = $status | Select-Object AMServiceEnabled, AntivirusEnabled, "
                "RealTimeProtectionEnabled, NISEnabled }; "
                "$result | ConvertTo-Json -Compress"
            ),
            (
                "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, "
                "RealTimeProtectionEnabled, NISEnabled | ConvertTo-Json -Compress"
            ),
        )
        try:
            status = self._first_powershell_result(commands, "Microsoft Defender")
            if status.get("Available") is False:
                return SecurityCheck(
                    "defender",
                    "Microsoft Defender",
                    "unavailable",
                    "Provider unavailable",
                    "Windows did not expose the Microsoft Defender status provider.",
                    "Confirm that Microsoft Defender is installed and not replaced by another endpoint-security product.",
                ).to_dict()
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
            enabled = self._registry_dword(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
            ) == 1
            if enabled:
                return SecurityCheck("uac", "User Account Control", "pass", "Enabled", "EnableLUA is enabled in the local system policy.", "Keep UAC enabled and use standard accounts for routine work.").to_dict()
            return SecurityCheck("uac", "User Account Control", "warning", "Disabled", "EnableLUA is disabled in the local system policy.", "Review the impact of enabling UAC with the system administrator.").to_dict()
        except RuntimeError as exc:
            return _unavailable("uac", "User Account Control", exc)

    def _bitlocker(self) -> dict[str, str]:
        try:
            drive = os.environ.get("SystemDrive", "C:")
            completed = self._run_native(["manage-bde.exe", "-status", drive], timeout=10)
            output = "\n".join(
                part.strip()
                for part in (completed.stdout, completed.stderr)
                if part and part.strip()
            )
            normalized = output.casefold()
            no_volume_markers = (
                "does not have an associated bitlocker volume",
                "not a bitlocker volume",
                "未与 bitlocker 卷关联",
                "不是 bitlocker 卷",
            )
            if any(marker in normalized for marker in no_volume_markers):
                return SecurityCheck(
                    "bitlocker",
                    "BitLocker",
                    "warning",
                    "Not configured",
                    "The system drive is not exposed as a BitLocker-managed volume.",
                    "Confirm the Windows edition and decide whether system-drive encryption is required.",
                ).to_dict()
            if completed.returncode != 0:
                raise RuntimeError(_compact_message(output or "manage-bde failed."))

            protected = any(
                marker in normalized
                for marker in ("protection on", "保护已启用", "保护状态: 已启用")
            )
            encrypted = any(
                marker in normalized
                for marker in ("fully encrypted", "已完全加密")
            )
            if protected and encrypted:
                return SecurityCheck("bitlocker", "BitLocker", "pass", "System drive protected", "System drive encryption and protection are enabled.", "Escrow recovery keys according to the approved policy.").to_dict()
            protection_off = any(
                marker in normalized
                for marker in ("protection off", "保护已关闭", "保护状态: 关闭")
            )
            decrypted = any(
                marker in normalized
                for marker in ("fully decrypted", "已完全解密")
            )
            state_detail = "BitLocker protection is disabled or encryption is incomplete."
            if not (protection_off or decrypted):
                state_detail = f"BitLocker returned a status that needs review: {_compact_message(output, 280)}"
            return SecurityCheck("bitlocker", "BitLocker", "warning", "Protection incomplete", state_detail, "Review system-drive encryption requirements with the device owner.").to_dict()
        except RuntimeError as exc:
            return _unavailable("bitlocker", "BitLocker", exc)

    def _first_powershell_result(
        self,
        commands: tuple[str, ...],
        label: str,
    ) -> dict[str, Any]:
        errors: list[str] = []
        for command in commands:
            try:
                result = self._powershell_json(command)
                if isinstance(result, dict):
                    return result
                errors.append("PowerShell returned an unexpected list.")
            except RuntimeError as exc:
                errors.append(_compact_message(str(exc), 260))
        raise RuntimeError(f"{label} status query failed: {_compact_message(' | '.join(errors), 520)}")

    def _registry_dword(self, path: str, name: str) -> int:
        try:
            import winreg

            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
                value, _value_type = winreg.QueryValueEx(key, name)
            return int(value)
        except (ImportError, OSError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Could not read HKLM\\{path}\\{name}: {_compact_message(str(exc))}") from exc

    def _run_native(
        self,
        command: list[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{command[0]} status query timed out after {timeout} seconds.") from exc
        except OSError as exc:
            raise RuntimeError(f"{command[0]} is unavailable: {_compact_message(str(exc))}") from exc

    def _service_running(self, service_name: str) -> bool | None:
        try:
            completed = self._run_native(["sc.exe", "query", service_name], timeout=5)
        except RuntimeError:
            return None
        if completed.returncode != 0:
            return None
        output = f"{completed.stdout}\n{completed.stderr}"
        match = re.search(r"(?im)\b(?:STATE|状态)\s*:\s*(\d+)", output)
        if match is None:
            return None
        return int(match.group(1)) == 4

    def _powershell_json(self, command: str) -> dict[str, Any] | list[dict[str, Any]]:
        script = (
            "$ProgressPreference='SilentlyContinue'; "
            "$ErrorActionPreference='Stop'; "
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
            f"{command}"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=12,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("PowerShell status query timed out after 12 seconds.") from exc
        except OSError as exc:
            raise RuntimeError(f"PowerShell is unavailable: {exc}") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "PowerShell command failed."
            raise RuntimeError(_compact_message(message))
        output = completed.stdout.strip()
        if not output:
            message = completed.stderr.strip()
            if message:
                raise RuntimeError(_compact_message(message))
            raise RuntimeError("PowerShell returned no status data.")
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            preview = " ".join(output.split())[:240]
            raise RuntimeError(f"PowerShell did not return valid JSON: {preview}") from exc
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
        powershell_error = ""
        try:
            command = (
                f"Get-Process | Select-Object -First {limit} Id, ProcessName, Path, WorkingSet64 "
                "| ConvertTo-Json -Compress"
            )
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                payload = json.loads(completed.stdout)
                rows = payload if isinstance(payload, list) else [payload]
                return [
                    {
                        "pid": int(row.get("Id", 0)),
                        "name": str(row.get("ProcessName") or "Unknown"),
                        "memory": _format_bytes(int(row.get("WorkingSet64") or 0)),
                        "path": str(row.get("Path") or ""),
                    }
                    for row in rows
                    if isinstance(row, dict) and int(row.get("Id", 0)) >= 0
                ][:limit]
            powershell_error = completed.stderr.strip() or completed.stdout.strip()
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, TypeError, ValueError) as exc:
            powershell_error = str(exc)

        try:
            completed = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Could not read the Windows process list: {powershell_error or exc}") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip() or powershell_error or "Could not read the Windows process list."
            raise RuntimeError(message)
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
    recommendation = "Verify Windows support, endpoint-security policy, and local administrator permissions."
    if os.name == "nt" and not is_process_elevated():
        recommendation = (
            "Stop any existing local API on port 8787, then start modern_main.py from an elevated PowerShell."
        )
    return SecurityCheck(identifier, title, "unavailable", "Unavailable", _compact_message(str(exc), 520), recommendation).to_dict()


def is_process_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _compact_message(value: str, limit: int = 360) -> str:
    compact = " ".join(str(value or "").split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"
