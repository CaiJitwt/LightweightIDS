from __future__ import annotations

import json
from threading import Thread
from urllib.request import Request, urlopen

from detection.engine import DetectionEngine
from modern_ui.local_api import LocalApiServer
from storage.database import Database
from storage.repositories import SettingsRepository


class _TestSecretStore:
    def protect(self, secret: str) -> str:
        return f"protected:{secret[::-1]}"

    def unprotect(self, protected_secret: str) -> str:
        return protected_secret.removeprefix("protected:")[::-1]


class _RecordingGuidanceService:
    def __init__(self) -> None:
        self.payload = None

    def generate(self, payload):
        self.payload = payload
        return {"guidance": "Review and contain the affected host."}


def test_minimum_alert_severity_is_persisted_and_exposed_by_local_api(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        with urlopen(f"{base}/api/settings", timeout=3) as response:
            defaults = json.loads(response.read())
        assert defaults["minimumAlertSeverity"] == "LOW"

        request = Request(
            f"{base}/api/settings",
            data=json.dumps({"minimumAlertSeverity": "HIGH", "alertCooldownSeconds": 25}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            saved = json.loads(response.read())

        assert saved["minimumAlertSeverity"] == "HIGH"
        assert saved["alertCooldownSeconds"] == 25
        assert SettingsRepository(database).get("minimum_alert_severity") == "HIGH"
        engine = DetectionEngine.from_rule_records([], minimum_severity="HIGH")
        assert engine.noise_reducer.minimum_severity == "HIGH"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_llm_settings_are_protected_persisted_and_not_returned(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    server = LocalApiServer(("127.0.0.1", 0), database)
    server.secret_store = _TestSecretStore()
    guidance = _RecordingGuidanceService()
    server.llm_guidance = guidance
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        request = Request(
            f"{base}/api/settings",
            data=json.dumps(
                {
                    "llmBaseUrl": "https://llm.example/v1",
                    "llmModel": "defender-model",
                    "llmApiKey": "secret-value",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            saved = json.loads(response.read())

        assert saved["llmBaseUrl"] == "https://llm.example/v1"
        assert saved["llmModel"] == "defender-model"
        assert saved["llmApiKeyConfigured"] is True
        assert "llmApiKey" not in saved
        stored = SettingsRepository(database).get("llm_api_key_protected")
        assert stored == "protected:eulav-terces"
        assert "secret-value" not in stored

        guidance_request = Request(
            f"{base}/api/llm/defense-guidance",
            data=json.dumps({"settings": {"apiKey": "browser-injected"}, "alert": {"rule": "Host scan"}}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(guidance_request, timeout=3) as response:
            result = json.loads(response.read())

        assert result["guidance"] == "Review and contain the affected host."
        assert guidance.payload["settings"] == {
            "baseUrl": "https://llm.example/v1",
            "apiKey": "secret-value",
            "model": "defender-model",
        }
        assert guidance.payload["alert"] == {"rule": "Host scan"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
