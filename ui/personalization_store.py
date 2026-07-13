from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import shutil

from PySide6.QtGui import QImageReader

from storage.database import Database
from storage.repositories import SettingsRepository
from ui.theme_manager import ThemeState


@dataclass
class PetState:
    image_path: str = ""
    visible: bool = False
    position: str = "bottom-right"
    size: int = 120
    opacity: float = 1.0


@dataclass
class PersonalizationState:
    schema_version: int = 1
    theme: ThemeState = field(default_factory=ThemeState)
    pet: PetState = field(default_factory=PetState)


class PersonalizationStore:
    SETTINGS_KEY = "personalization.state.v1"
    MAX_RESOURCE_BYTES = 25 * 1024 * 1024
    RESOURCE_PREFIX = "managed:"
    VALID_RESOURCE_KINDS = {"wallpapers", "pets"}
    VALID_POSITIONS = {"center", "top-left", "top-right", "bottom-left", "bottom-right"}
    VALID_SIZES = {"cover", "contain", "stretch", "original"}
    VALID_PET_POSITIONS = {"bottom-right", "bottom-left", "top-right", "top-left"}

    def __init__(self, database: Database, resource_root: str | Path | None = None) -> None:
        self.settings = SettingsRepository(database)
        self.resource_root = Path(resource_root) if resource_root else database.path.parent / "personalization"
        self._ensure_directories()

    def load(self) -> PersonalizationState:
        raw = self.settings.get(self.SETTINGS_KEY)
        if not raw:
            return PersonalizationState()
        try:
            payload = json.loads(raw)
            theme_data = payload.get("theme", {})
            pet_data = payload.get("pet", {})
            state = PersonalizationState(
                schema_version=int(payload.get("schema_version", 1)),
                theme=ThemeState(
                    background_color=self._valid_color(theme_data.get("background_color")),
                    background_image=self._decode_path(str(theme_data.get("background_image") or "")),
                    background_position=self._choice(
                        theme_data.get("background_position"), self.VALID_POSITIONS, "center"
                    ),
                    background_size=self._choice(theme_data.get("background_size"), self.VALID_SIZES, "cover"),
                    background_opacity=self._float_range(theme_data.get("background_opacity"), 0.1, 1.0, 1.0),
                    overlay_color=self._valid_color(theme_data.get("overlay_color"), allow_empty=True),
                    mode=self._choice(theme_data.get("mode"), {"light", "dark"}, "light"),
                ),
                pet=PetState(
                    image_path=self._decode_path(str(pet_data.get("image_path") or "")),
                    visible=bool(pet_data.get("visible", False)),
                    position=self._choice(
                        pet_data.get("position"), self.VALID_PET_POSITIONS, "bottom-right"
                    ),
                    size=self._int_range(pet_data.get("size"), 32, 320, 120),
                    opacity=self._float_range(pet_data.get("opacity"), 0.1, 1.0, 1.0),
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return PersonalizationState()

        if state.theme.background_image and not Path(state.theme.background_image).is_file():
            state.theme.background_image = ""
        if state.pet.image_path and not Path(state.pet.image_path).is_file():
            state.pet.image_path = ""
            state.pet.visible = False
        return state

    def save(self, theme: ThemeState, pet: PetState) -> None:
        theme_data = asdict(theme)
        theme_data["background_image"] = self._encode_path(theme.background_image)
        pet_data = asdict(pet)
        pet_data["image_path"] = self._encode_path(pet.image_path)
        payload = {
            "schema_version": 1,
            "theme": theme_data,
            "pet": pet_data,
        }
        self.settings.set(self.SETTINGS_KEY, json.dumps(payload, ensure_ascii=True, separators=(",", ":")))

    def import_resource(self, source_path: str | Path, kind: str) -> str:
        if kind not in self.VALID_RESOURCE_KINDS:
            raise ValueError(f"Unsupported personalization resource kind: {kind}")
        source = Path(source_path).expanduser().resolve()
        if not source.is_file():
            raise ValueError("The selected image does not exist.")
        if source.stat().st_size > self.MAX_RESOURCE_BYTES:
            raise ValueError("The selected image is larger than 25 MB.")
        if not QImageReader(str(source)).canRead():
            raise ValueError("The selected file is not a supported readable image.")

        digest = self._sha256(source)
        suffix = source.suffix.lower() if source.suffix else ".img"
        destination = self.resource_root / kind / f"{digest}{suffix}"
        if not destination.exists():
            temporary = destination.with_suffix(destination.suffix + ".tmp")
            shutil.copy2(source, temporary)
            temporary.replace(destination)
        return str(destination.resolve())

    def remove_managed_resource(self, resource_path: str) -> None:
        if not resource_path:
            return
        candidate = Path(resource_path).resolve()
        try:
            candidate.relative_to(self.resource_root.resolve())
        except ValueError:
            return
        if candidate.is_file():
            candidate.unlink()

    def _ensure_directories(self) -> None:
        for kind in self.VALID_RESOURCE_KINDS:
            (self.resource_root / kind).mkdir(parents=True, exist_ok=True)

    def _encode_path(self, value: str) -> str:
        if not value:
            return ""
        path = Path(value).resolve()
        try:
            relative = path.relative_to(self.resource_root.resolve())
        except ValueError:
            return str(path)
        return f"{self.RESOURCE_PREFIX}{relative.as_posix()}"

    def _decode_path(self, value: str) -> str:
        if not value:
            return ""
        if value.startswith(self.RESOURCE_PREFIX):
            relative = value[len(self.RESOURCE_PREFIX) :]
            candidate = (self.resource_root / relative).resolve()
            try:
                candidate.relative_to(self.resource_root.resolve())
            except ValueError:
                return ""
            return str(candidate)
        return str(Path(value).expanduser())

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _choice(self, value: object, choices: set[str], default: str) -> str:
        candidate = str(value or "")
        return candidate if candidate in choices else default

    def _valid_color(self, value: object, *, allow_empty: bool = False) -> str:
        candidate = str(value or "").strip()
        if allow_empty and not candidate:
            return ""
        if len(candidate) in {4, 7, 9} and candidate.startswith("#"):
            try:
                int(candidate[1:], 16)
                return candidate
            except ValueError:
                pass
        return "#f6f7f9"

    def _float_range(self, value: object, minimum: float, maximum: float, default: float) -> float:
        try:
            return max(minimum, min(float(value), maximum))
        except (TypeError, ValueError):
            return default

    def _int_range(self, value: object, minimum: int, maximum: int, default: int) -> int:
        try:
            return max(minimum, min(int(value), maximum))
        except (TypeError, ValueError):
            return default
