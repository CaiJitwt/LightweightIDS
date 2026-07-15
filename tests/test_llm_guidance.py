from __future__ import annotations

import json

from modern_ui.llm_guidance import LlmGuidanceService


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_llm_guidance_forwards_only_normalized_alert_metadata(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout: int):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _Response({"choices": [{"message": {"content": "Isolate the host and validate the alert."}}]})

    monkeypatch.setattr("modern_ui.llm_guidance.urlopen", fake_urlopen)
    response = LlmGuidanceService().generate(
        {
            "settings": {"baseUrl": "https://llm.example/v1", "apiKey": "secret", "model": "defender-model"},
            "alert": {"rule": "Host scan", "severity": "HIGH", "description": "Many targets", "unexpected": "not forwarded"},
        }
    )

    assert response["guidance"] == "Isolate the host and validate the alert."
    assert captured["url"] == "https://llm.example/v1/chat/completions"
    assert "Respond in English." in captured["body"]["messages"][0]["content"]
    user_payload = json.loads(captured["body"]["messages"][1]["content"])
    assert user_payload["rule"] == "Host scan"
    assert "unexpected" not in user_payload


def test_llm_guidance_can_request_simplified_chinese(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout: int):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _Response({"choices": [{"message": {"content": "请隔离主机并核实告警。"}}]})

    monkeypatch.setattr("modern_ui.llm_guidance.urlopen", fake_urlopen)
    response = LlmGuidanceService().generate(
        {
            "settings": {"baseUrl": "https://llm.example/v1", "apiKey": "secret", "model": "defender-model"},
            "alert": {"rule": "Host scan", "severity": "HIGH"},
            "language": "zh",
        }
    )

    assert response["guidance"] == "请隔离主机并核实告警。"
    assert "Respond in Simplified Chinese." in captured["body"]["messages"][0]["content"]
