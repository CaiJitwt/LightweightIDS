from __future__ import annotations

import json
from types import SimpleNamespace

from endpoint_security.posture import EndpointPostureService, ProcessInventoryService


def test_endpoint_posture_is_explicitly_unavailable_off_windows():
    checks = EndpointPostureService(is_windows=False).collect()
    assert checks[0]["state"] == "unavailable"
    assert checks[0]["identifier"] == "platform"


def test_endpoint_posture_normalizes_successful_windows_checks(monkeypatch):
    service = EndpointPostureService(is_windows=True)

    def fake_powershell(command: str):
        if "Get-NetFirewallProfile" in command:
            return [{"Name": "Domain", "Enabled": True}, {"Name": "Public", "Enabled": True}]
        if "Get-MpComputerStatus" in command:
            return {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "NISEnabled": True}
        if "EnableLUA" in command:
            return {"EnableLUA": 1}
        return {"VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On"}

    monkeypatch.setattr(service, "_powershell_json", fake_powershell)
    checks = service.collect()
    assert {check["state"] for check in checks} == {"pass"}


def test_process_inventory_uses_non_admin_powershell_metadata(monkeypatch):
    payload = [{"Id": 42, "ProcessName": "python", "Path": "C:\\Python\\python.exe", "WorkingSet64": 2_097_152}]

    def fake_run(command, **_kwargs):
        assert command[0] == "powershell"
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("endpoint_security.posture.subprocess.run", fake_run)
    records = ProcessInventoryService(is_windows=True).list_processes(10)
    assert records == [{"pid": 42, "name": "python", "memory": "2.0 MB", "path": "C:\\Python\\python.exe"}]
