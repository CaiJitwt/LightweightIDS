from __future__ import annotations

from endpoint_security.posture import EndpointPostureService


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
