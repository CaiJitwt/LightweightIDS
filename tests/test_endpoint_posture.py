from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from endpoint_security.posture import EndpointPostureService, ProcessInventoryService


def test_endpoint_posture_is_explicitly_unavailable_off_windows():
    checks = EndpointPostureService(is_windows=False).collect()
    assert checks[0]["state"] == "unavailable"
    assert checks[0]["identifier"] == "platform"


def test_endpoint_posture_normalizes_successful_windows_checks(monkeypatch):
    service = EndpointPostureService(is_windows=True)

    def fake_powershell(command: str):
        if "Microsoft/Windows/Defender" in command or "Get-MpComputerStatus" in command:
            return {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "NISEnabled": True}
        raise AssertionError(f"Unexpected PowerShell command: {command}")

    monkeypatch.setattr(service, "_powershell_json", fake_powershell)
    monkeypatch.setattr(service, "_registry_dword", lambda _path, _name: 1)
    monkeypatch.setattr(
        service,
        "_run_native",
        lambda command, timeout: (
            SimpleNamespace(returncode=0, stdout="STATE : 4 RUNNING", stderr="")
            if command[0] == "sc.exe"
            else SimpleNamespace(
                returncode=0,
                stdout="Conversion Status: Fully Encrypted\nProtection Status: Protection On",
                stderr="",
            )
        ),
    )
    checks = service.collect()
    assert {check["state"] for check in checks} == {"pass"}


def test_endpoint_posture_reports_unmanaged_bitlocker_volume(monkeypatch):
    service = EndpointPostureService(is_windows=True)
    monkeypatch.setattr(
        service,
        "_run_native",
        lambda _command, timeout: SimpleNamespace(
            returncode=1,
            stdout="C: does not have an associated BitLocker volume.",
            stderr="",
        ),
    )

    check = service._bitlocker()

    assert check["state"] == "warning"
    assert check["value"] == "Not configured"


def test_endpoint_posture_reads_firewall_without_powershell(monkeypatch):
    service = EndpointPostureService(is_windows=True)
    values = iter((1, 0, 1))
    monkeypatch.setattr(service, "_registry_dword", lambda _path, _name: next(values))

    check = service._firewall()

    assert check["state"] == "fail"
    assert check["detail"] == "Disabled profiles: Private."


def test_endpoint_posture_reports_stopped_defender_as_externally_managed(monkeypatch):
    service = EndpointPostureService(is_windows=True)
    monkeypatch.setattr(service, "_service_running", lambda _name: False)

    check = service._defender()

    assert check["state"] == "warning"
    assert check["value"] == "Inactive or externally managed"


def test_powershell_json_surfaces_stderr_when_command_returns_no_json(monkeypatch):
    service = EndpointPostureService(is_windows=True)
    monkeypatch.setattr(
        "endpoint_security.posture.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr="Access denied"),
    )

    with pytest.raises(RuntimeError, match="Access denied"):
        service._powershell_json("Get-BitLockerVolume | ConvertTo-Json")


def test_process_inventory_uses_non_admin_powershell_metadata(monkeypatch):
    payload = [{"Id": 42, "ProcessName": "python", "Path": "C:\\Python\\python.exe", "WorkingSet64": 2_097_152}]

    def fake_run(command, **_kwargs):
        assert command[0] == "powershell"
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("endpoint_security.posture.subprocess.run", fake_run)
    records = ProcessInventoryService(is_windows=True).list_processes(10)
    assert records == [{"pid": 42, "name": "python", "memory": "2.0 MB", "path": "C:\\Python\\python.exe"}]
