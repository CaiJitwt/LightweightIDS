from __future__ import annotations

import json
from threading import Thread
from urllib.request import Request, urlopen

from detection.engine import DetectionEngine
from modern_ui.local_api import LocalApiServer
from storage.database import Database
from storage.repositories import SettingsRepository


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
