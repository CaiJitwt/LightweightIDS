from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LlmConfig:
    provider: str = "ollama"
    api_url: str = "http://localhost:11434"
    api_key: str = ""
    model: str = ""
    enabled: bool = True
    timeout: int = 30

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "api_url": self.api_url,
            "api_key": self.api_key,
            "model": self.model,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LlmConfig":
        return cls(
            provider=str(data.get("provider", "ollama")),
            api_url=str(data.get("api_url", "http://localhost:11434")),
            api_key=str(data.get("api_key", "")),
            model=str(data.get("model", "")),
            enabled=bool(data.get("enabled", True)),
        )

    @classmethod
    def from_settings(cls, repository: object | None = None) -> "LlmConfig":
        if repository is None:
            return cls()
        return cls(
            provider=repository.get("llm_provider", "ollama") or "ollama",
            api_url=repository.get("llm_api_url", "http://localhost:11434") or "http://localhost:11434",
            model=repository.get("llm_model", "") or "",
            enabled=repository.get_bool("llm_enabled", True) if hasattr(repository, "get_bool") else True,
        )


class LlmClient:
    def __init__(self, config: LlmConfig | None = None) -> None:
        self.config = config or LlmConfig()

    def chat(self, prompt: str, system: str = "") -> str | None:
        if not self.config.enabled:
            return None
        if self.config.provider == "ollama":
            return self._call_ollama(prompt, system)
        if self.config.provider == "openai":
            return self._call_openai(prompt, system)
        return None

    def test_connection(self) -> dict[str, Any]:
        if self.config.provider == "ollama":
            return self._test_ollama()
        if self.config.provider == "openai":
            return self._test_openai()
        return {"ok": False, "error": f"Unknown provider: {self.config.provider}"}

    def list_models(self) -> list[str]:
        if self.config.provider == "ollama":
            return self._list_ollama_models()
        return []

    # ---- Ollama ----

    def _call_ollama(self, prompt: str, system: str) -> str | None:
        try:
            import requests
        except ImportError:
            return None

        url = f"{self.config.api_url}/api/generate"
        payload: dict[str, Any] = {
            "model": self.config.model or "llama3.2",
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        try:
            resp = requests.post(url, json=payload, timeout=self.config.timeout)
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
        except Exception:
            pass
        return None

    def _test_ollama(self) -> dict[str, Any]:
        try:
            import requests
        except ImportError:
            return {"ok": False, "error": "requests library not installed"}
        try:
            resp = requests.get(f"{self.config.api_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return {"ok": False, "error": f"HTTP {resp.status_code}"}
            models = resp.json().get("models", [])
            names = [m.get("name", "") for m in models]
            target = self.config.model
            if not target:
                return {"ok": True, "available": names}
            if any(target in name or name.startswith(target) for name in names):
                return {"ok": True, "model": target}
            return {"ok": True, "available": names, "hint": f"Model {target} not found"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _list_ollama_models(self) -> list[str]:
        try:
            import requests
        except ImportError:
            return []
        try:
            resp = requests.get(f"{self.config.api_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                return [m.get("name", "") for m in resp.json().get("models", [])]
        except Exception:
            pass
        return []

    # ---- OpenAI ----

    def _call_openai(self, prompt: str, system: str) -> str | None:
        try:
            import requests
        except ImportError:
            return None

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = requests.post(
                f"{self.config.api_url}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.config.api_key}",
                },
                json={"model": self.config.model or "gpt-4o-mini", "messages": messages},
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass
        return None

    def _test_openai(self) -> dict[str, Any]:
        try:
            import requests
        except ImportError:
            return {"ok": False, "error": "requests library not installed"}
        try:
            resp = requests.post(
                f"{self.config.api_url}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.config.api_key}",
                },
                json={"model": self.config.model or "gpt-4o-mini", "messages": [{"role": "user", "content": "reply OK"}]},
                timeout=10,
            )
            if resp.status_code == 200:
                return {"ok": True, "model": self.config.model}
            err = resp.json().get("error", {}).get("message", f"HTTP {resp.status_code}")
            return {"ok": False, "error": str(err)}
        except Exception as e:
            return {"ok": False, "error": str(e)}
