from __future__ import annotations

import base64
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
        assert defaults["themePreference"] == "system"
        assert defaults["fontScale"] == "default"

        request = Request(
            f"{base}/api/settings",
            data=json.dumps(
                {
                    "minimumAlertSeverity": "HIGH",
                    "alertCooldownSeconds": 25,
                    "themePreference": "dark",
                    "fontScale": "comfortable",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            saved = json.loads(response.read())

        assert saved["minimumAlertSeverity"] == "HIGH"
        assert saved["alertCooldownSeconds"] == 25
        assert saved["themePreference"] == "dark"
        assert saved["fontScale"] == "comfortable"
        assert SettingsRepository(database).get("minimum_alert_severity") == "HIGH"
        assert SettingsRepository(database).get("modern_theme_preference") == "dark"
        assert SettingsRepository(database).get("modern_font_scale") == "comfortable"
        engine = DetectionEngine.from_rule_records([], minimum_severity="HIGH")
        assert engine.noise_reducer.minimum_severity == "HIGH"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_modern_personalization_and_wallpaper_survive_api_restart(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
        "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )

    def start_server():
        server = LocalApiServer(("127.0.0.1", 0), database)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        return server, thread, f"http://{host}:{port}"

    server, thread, base = start_server()
    try:
        image_request = Request(
            f"{base}/api/personalization/images/background",
            data=png,
            headers={"Content-Type": "image/png", "X-Filename": "wallpaper.png"},
            method="POST",
        )
        with urlopen(image_request, timeout=3) as response:
            uploaded = json.loads(response.read())
        assert uploaded["url"].startswith("/api/personalization/images/background?v=")

        state_request = Request(
            f"{base}/api/personalization",
            data=json.dumps(
                {
                    "accent": "#445566",
                    "componentOpacity": 81,
                    "componentBlur": 10,
                    "background": uploaded["url"],
                    "backgroundPosition": "top-left",
                    "backgroundSize": "contain",
                    "backgroundOpacity": 72,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(state_request, timeout=3) as response:
            saved = json.loads(response.read())

        assert saved["persisted"] is True
        assert saved["state"]["accent"] == "#445566"
        assert saved["state"]["componentOpacity"] == 81
        assert saved["state"]["backgroundPosition"] == "top-left"
        with urlopen(f"{base}{saved['state']['background']}", timeout=3) as response:
            assert response.headers["Content-Type"] == "image/png"
            assert response.read() == png
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    restarted, restarted_thread, restarted_base = start_server()
    try:
        with urlopen(f"{restarted_base}/api/personalization", timeout=3) as response:
            restored = json.loads(response.read())

        assert restored["persisted"] is True
        assert restored["state"]["accent"] == "#445566"
        assert restored["state"]["componentOpacity"] == 81
        assert restored["state"]["componentBlur"] == 10
        assert restored["state"]["backgroundPosition"] == "top-left"
        assert restored["state"]["backgroundSize"] == "contain"
        assert restored["state"]["backgroundOpacity"] == 72
        with urlopen(f"{restarted_base}{restored['state']['background']}", timeout=3) as response:
            assert response.read() == png
    finally:
        restarted.shutdown()
        restarted.server_close()
        restarted_thread.join(timeout=3)


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
            data=json.dumps({"settings": {"apiKey": "browser-injected"}, "alert": {"rule": "Host scan"}, "language": "zh"}).encode(),
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
        assert guidance.payload["language"] == "zh"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
