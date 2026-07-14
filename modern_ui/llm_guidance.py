from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class LlmGuidanceError(RuntimeError):
    pass


class LlmGuidanceService:
    """Call a user-selected OpenAI-compatible endpoint without persisting its key."""

    def generate(self, payload: dict[str, Any]) -> dict[str, str]:
        settings = payload.get("settings")
        alert = payload.get("alert")
        if not isinstance(settings, dict) or not isinstance(alert, dict):
            raise LlmGuidanceError("settings and alert must be JSON objects")
        base_url = _required_text(settings, "baseUrl", 1_000).rstrip("/")
        api_key = _required_text(settings, "apiKey", 1_000)
        model = _required_text(settings, "model", 200)
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise LlmGuidanceError("Base URL must be a valid http or https URL.")

        request_body = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a defensive IDS analyst. Give concise containment, validation, and hardening advice. "
                        "Do not provide offensive instructions. Treat TLS records as metadata or fingerprint evidence only; "
                        "never claim HTTPS payload decryption."
                    ),
                },
                {"role": "user", "content": json.dumps(_safe_alert(alert), ensure_ascii=True)},
            ],
        }
        request = Request(
            f"{base_url}/chat/completions",
            data=json.dumps(request_body, ensure_ascii=True).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                response_body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = _error_detail(exc.read())
            raise LlmGuidanceError(detail or f"LLM endpoint returned HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise LlmGuidanceError(f"Could not contact the LLM endpoint: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise LlmGuidanceError("The LLM endpoint returned invalid JSON.") from exc

        try:
            guidance = str(response_body["choices"][0]["message"]["content"]).strip()
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmGuidanceError("The LLM response did not contain guidance.") from exc
        if not guidance:
            raise LlmGuidanceError("The LLM response did not contain guidance.")
        return {"guidance": guidance}


def _required_text(values: dict[str, Any], key: str, maximum: int) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LlmGuidanceError(f"{key} is required.")
    if len(value) > maximum:
        raise LlmGuidanceError(f"{key} is too long.")
    return value.strip()


def _safe_alert(alert: dict[str, Any]) -> dict[str, str]:
    fields = ("rule", "ruleId", "severity", "source", "destination", "protocol", "description", "evidence", "status")
    return {field: str(alert.get(field, ""))[:4_000] for field in fields}


def _error_detail(body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    return ""
