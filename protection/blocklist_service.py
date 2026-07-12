from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Callable

from models import BlocklistEntry
from storage.blocklist_repository import BlocklistEntryRepository
from storage.database import Database


@dataclass(frozen=True)
class EnforcementResult:
    success: bool
    status: str
    message: str = ""


class WindowsFirewallEnforcer:
    RULE_PREFIX = "Lightweight IDS Block"

    def __init__(self, runner: Callable[[list[str]], tuple[int, str]] | None = None) -> None:
        self.runner = runner or self._run

    def enforce(self, entry: BlocklistEntry) -> EnforcementResult:
        if sys.platform != "win32":
            return EnforcementResult(False, "Unsupported", "Automatic enforcement is currently available on Windows only.")
        if entry.id is None:
            return EnforcementResult(False, "Failed", "Blocklist entry must be saved before enforcement.")
        self.remove(entry, ignore_errors=True)
        for name, arguments in self._rule_specs(entry):
            code, output = self.runner(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", *arguments]
            )
            if code != 0:
                self.remove(entry, ignore_errors=True)
                return EnforcementResult(False, "Failed", output or "Windows Firewall rejected the rule.")
        return EnforcementResult(True, "Active", "Windows Firewall rules are active.")

    def remove(self, entry: BlocklistEntry, ignore_errors: bool = False) -> EnforcementResult:
        if sys.platform != "win32":
            return EnforcementResult(False, "Unsupported", "Automatic enforcement is currently available on Windows only.")
        failures: list[str] = []
        for name, _arguments in self._rule_specs(entry):
            code, output = self.runner(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
            )
            if code != 0 and not ignore_errors:
                failures.append(output)
        if failures:
            return EnforcementResult(False, "Failed", "; ".join(value for value in failures if value))
        return EnforcementResult(True, "Removed", "Windows Firewall rules were removed.")

    def _rule_specs(self, entry: BlocklistEntry) -> list[tuple[str, list[str]]]:
        base = f"{self.RULE_PREFIX} {entry.id}"
        if entry.kind == "IP":
            inbound_ip_argument = "remoteip" if entry.field == "SRC_IP" else "localip"
            outbound_ip_argument = "localip" if entry.field == "SRC_IP" else "remoteip"
            return [
                (f"{base} inbound", ["dir=in", "action=block", "protocol=any", f"{inbound_ip_argument}={entry.value}"]),
                (f"{base} outbound", ["dir=out", "action=block", "protocol=any", f"{outbound_ip_argument}={entry.value}"]),
            ]
        protocols = [entry.protocol] if entry.protocol in {"TCP", "UDP"} else ["TCP", "UDP"]
        specs: list[tuple[str, list[str]]] = []
        for protocol in protocols:
            if entry.field == "SRC_PORT":
                specs.extend(
                    [
                        (f"{base} {protocol} inbound", ["dir=in", "action=block", f"protocol={protocol}", f"remoteport={entry.value}"]),
                        (f"{base} {protocol} outbound", ["dir=out", "action=block", f"protocol={protocol}", f"localport={entry.value}"]),
                    ]
                )
            else:
                specs.extend(
                    [
                        (f"{base} {protocol} inbound", ["dir=in", "action=block", f"protocol={protocol}", f"localport={entry.value}"]),
                        (f"{base} {protocol} outbound", ["dir=out", "action=block", f"protocol={protocol}", f"remoteport={entry.value}"]),
                    ]
                )
        return specs

    def _run(self, arguments: list[str]) -> tuple[int, str]:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            creationflags=creation_flags,
        )
        output = (completed.stderr or completed.stdout or "").strip()
        return completed.returncode, output


class BlocklistService:
    def __init__(self, database: Database, enforcer: WindowsFirewallEnforcer | None = None) -> None:
        self.repository = BlocklistEntryRepository(database)
        self.enforcer = enforcer or WindowsFirewallEnforcer()

    def add_and_enforce(self, *, kind: str, value: str, field: str, protocol: str = "ANY") -> tuple[BlocklistEntry, EnforcementResult]:
        entry = self.repository.add(BlocklistEntry(kind=kind, value=value, field=field, protocol=protocol))
        result = self.enforcer.enforce(entry)
        self.repository.update_enforcement(entry.id or 0, result.status, result.message if not result.success else "")
        entry.enforcement_status = result.status
        entry.enforcement_error = "" if result.success else result.message
        return entry, result

    def retry(self, entry_id: int) -> EnforcementResult:
        entry = self.repository.get(entry_id)
        if entry is None:
            return EnforcementResult(False, "Failed", "Blocklist entry not found.")
        result = self.enforcer.enforce(entry)
        self.repository.update_enforcement(entry_id, result.status, result.message if not result.success else "")
        return result

    def remove(self, entry_id: int) -> EnforcementResult:
        entry = self.repository.get(entry_id)
        if entry is None:
            return EnforcementResult(False, "Failed", "Blocklist entry not found.")
        result = self.enforcer.remove(entry)
        if result.success or result.status == "Unsupported":
            self.repository.delete(entry_id)
        else:
            self.repository.update_enforcement(entry_id, result.status, result.message)
        return result
