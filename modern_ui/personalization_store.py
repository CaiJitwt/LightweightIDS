from __future__ import annotations

import json
from pathlib import Path
from typing import BinaryIO

from storage.database import Database
from storage.repositories import SettingsRepository


DEFAULT_PERSONALIZATION: dict[str, object] = {
    "accent": "#2677bd",
    "componentTint": "#7ea7c4",
    "componentOpacity": 92,
    "componentBlur": 6,
    "tableTint": "#8ca6b8",
    "tableOpacity": 94,
    "tableBlur": 4,
    "backgroundPosition": "center",
    "backgroundSize": "cover",
    "backgroundOpacity": 100,
    "petPosition": "bottom-right",
    "petSize": 96,
    "petOpacity": 85,
}


class ModernPersonalizationStore:
    SETTINGS_KEY = "modern.personalization.v1"
    MAX_IMAGE_BYTES = 50 * 1024 * 1024
    IMAGE_TYPES = {
        "image/png": (".png", b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": (".jpg", b"\xff\xd8\xff"),
        "image/webp": (".webp", b"RIFF"),
    }
    IMAGE_KINDS = {"background", "petImage"}
    POSITIONS = {"center", "top-left", "top-right", "bottom-left", "bottom-right"}
    SIZES = {"cover", "contain", "stretch", "original"}
    PET_POSITIONS = {"bottom-right", "bottom-left", "top-right", "top-left"}

    def __init__(self, database: Database) -> None:
        self.settings = SettingsRepository(database)
        self.resource_root = database.path.parent / "personalization" / "modern"
        self.resource_root.mkdir(parents=True, exist_ok=True)

    def load(self) -> tuple[dict[str, object], bool]:
        raw = self.settings.get(self.SETTINGS_KEY)
        persisted = bool(raw)
        config: dict[str, object] = {}
        if raw:
            try:
                decoded = json.loads(raw)
                if isinstance(decoded, dict):
                    config = decoded
            except json.JSONDecodeError:
                config = {}
        state = self._validated_state(config)
        for kind in self.IMAGE_KINDS:
            image_path = self.image_path(kind)
            state[kind] = self._image_url(kind, image_path) if image_path else ""
            persisted = persisted or image_path is not None
        return state, persisted

    def save(self, payload: dict[str, object]) -> dict[str, object]:
        current, _ = self.load()
        state = self._validated_state({**current, **payload})
        for kind in self.IMAGE_KINDS:
            if kind in payload and not payload.get(kind):
                self.remove_image(kind)
        self.settings.set(
            self.SETTINGS_KEY,
            json.dumps(
                {key: state[key] for key in DEFAULT_PERSONALIZATION},
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        )
        return self.load()[0]

    def store_image(self, kind: str, content_type: str, source: BinaryIO, length: int) -> dict[str, object]:
        if kind not in self.IMAGE_KINDS:
            raise ValueError("Unsupported personalization image kind.")
        normalized_type = content_type.split(";", 1)[0].strip().lower()
        if normalized_type not in self.IMAGE_TYPES:
            raise ValueError("Only PNG, JPEG, and WebP images are supported.")
        if length <= 0:
            raise ValueError("Choose a non-empty image.")
        if length > self.MAX_IMAGE_BYTES:
            raise ValueError("The image exceeds the 50 MB personalization limit.")

        suffix, signature = self.IMAGE_TYPES[normalized_type]
        destination = self.resource_root / f"{kind}{suffix}"
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        remaining = length
        with temporary.open("wb") as stream:
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                stream.write(chunk)
                remaining -= len(chunk)
        if remaining:
            temporary.unlink(missing_ok=True)
            raise ValueError("The image upload ended before all bytes were received.")
        header = temporary.read_bytes()[:12]
        valid_signature = header.startswith(signature)
        if normalized_type == "image/webp":
            valid_signature = valid_signature and header[8:12] == b"WEBP"
        if not valid_signature:
            temporary.unlink(missing_ok=True)
            raise ValueError("The uploaded file does not match its image type.")

        self.remove_image(kind)
        temporary.replace(destination)
        return {"url": self._image_url(kind, destination)}

    def image_path(self, kind: str) -> Path | None:
        if kind not in self.IMAGE_KINDS:
            return None
        for suffix, _signature in self.IMAGE_TYPES.values():
            candidate = self.resource_root / f"{kind}{suffix}"
            if candidate.is_file():
                return candidate
        return None

    def remove_image(self, kind: str) -> None:
        if kind not in self.IMAGE_KINDS:
            return
        for suffix, _signature in self.IMAGE_TYPES.values():
            (self.resource_root / f"{kind}{suffix}").unlink(missing_ok=True)

    def _validated_state(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "accent": self._color(payload.get("accent"), "#2677bd"),
            "componentTint": self._color(payload.get("componentTint"), "#7ea7c4"),
            "componentOpacity": self._integer(payload.get("componentOpacity"), 65, 100, 92),
            "componentBlur": self._integer(payload.get("componentBlur"), 0, 24, 6),
            "tableTint": self._color(payload.get("tableTint"), "#8ca6b8"),
            "tableOpacity": self._integer(payload.get("tableOpacity"), 65, 100, 94),
            "tableBlur": self._integer(payload.get("tableBlur"), 0, 24, 4),
            "backgroundPosition": self._choice(payload.get("backgroundPosition"), self.POSITIONS, "center"),
            "backgroundSize": self._choice(payload.get("backgroundSize"), self.SIZES, "cover"),
            "backgroundOpacity": self._integer(payload.get("backgroundOpacity"), 10, 100, 100),
            "petPosition": self._choice(payload.get("petPosition"), self.PET_POSITIONS, "bottom-right"),
            "petSize": self._integer(payload.get("petSize"), 48, 220, 96),
            "petOpacity": self._integer(payload.get("petOpacity"), 20, 100, 85),
        }

    @staticmethod
    def _color(value: object, default: str) -> str:
        candidate = str(value or "").strip().lower()
        if len(candidate) == 7 and candidate.startswith("#") and all(
            character in "0123456789abcdef" for character in candidate[1:]
        ):
            return candidate
        return default

    @staticmethod
    def _integer(value: object, minimum: int, maximum: int, default: int) -> int:
        try:
            return max(minimum, min(maximum, int(value)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _choice(value: object, choices: set[str], default: str) -> str:
        candidate = str(value or "")
        return candidate if candidate in choices else default

    @staticmethod
    def _image_url(kind: str, path: Path) -> str:
        return f"/api/personalization/images/{kind}?v={path.stat().st_mtime_ns}"
