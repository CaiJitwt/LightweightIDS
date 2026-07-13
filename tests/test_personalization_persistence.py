from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication

from storage.database import Database
from storage.repositories import SettingsRepository
from ui.main_window import MainWindow
from ui.personalization_store import PersonalizationStore, PetState
from ui.theme_manager import ThemeState


def create_image(path: Path, color: str = "#2563eb") -> None:
    image = QImage(32, 32, QImage.Format_ARGB32)
    image.fill(QColor(color))
    assert image.save(str(path), "PNG")


def test_personalization_store_copies_resources_and_uses_relative_managed_paths(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    source = tmp_path / "source.png"
    create_image(source)
    store = PersonalizationStore(database)

    wallpaper = store.import_resource(source, "wallpapers")
    pet_image = store.import_resource(source, "pets")
    store.save(
        ThemeState(
            background_color="#102030",
            background_image=wallpaper,
            background_position="top-right",
            background_size="contain",
            background_opacity=0.65,
        ),
        PetState(
            image_path=pet_image,
            visible=True,
            position="bottom-left",
            size=156,
            opacity=0.72,
        ),
    )

    raw = SettingsRepository(database).get(PersonalizationStore.SETTINGS_KEY)
    payload = json.loads(raw)
    restored = store.load()

    assert payload["theme"]["background_image"].startswith("managed:")
    assert payload["pet"]["image_path"].startswith("managed:")
    assert Path(wallpaper).is_file()
    assert Path(pet_image).is_file()
    assert restored.theme.background_image == wallpaper
    assert restored.theme.background_position == "top-right"
    assert restored.theme.background_opacity == 0.65
    assert restored.pet.image_path == pet_image
    assert restored.pet.visible is True
    assert restored.pet.position == "bottom-left"
    assert restored.pet.size == 156
    assert restored.pet.opacity == 0.72


def test_personalization_store_falls_back_when_saved_image_is_missing(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    source = tmp_path / "source.png"
    create_image(source)
    store = PersonalizationStore(database)
    wallpaper = store.import_resource(source, "wallpapers")
    pet_image = store.import_resource(source, "pets")
    store.save(ThemeState(background_image=wallpaper), PetState(image_path=pet_image, visible=True))
    Path(wallpaper).unlink()
    Path(pet_image).unlink()

    restored = store.load()

    assert restored.theme.background_image == ""
    assert restored.pet.image_path == ""
    assert restored.pet.visible is False


def test_main_window_restores_personalization_controls_and_overlay(tmp_path):
    app = QApplication.instance() or QApplication([])
    database = Database(tmp_path / "ids.db")
    database.initialize()
    source = tmp_path / "source.png"
    create_image(source, "#16a34a")
    store = PersonalizationStore(database)
    wallpaper = store.import_resource(source, "wallpapers")
    pet_image = store.import_resource(source, "pets")
    store.save(
        ThemeState(
            background_color="#112233",
            background_image=wallpaper,
            background_position="bottom-left",
            background_size="stretch",
            background_opacity=0.55,
        ),
        PetState(
            image_path=pet_image,
            visible=True,
            position="top-right",
            size=144,
            opacity=0.6,
        ),
    )

    window = MainWindow(database, {"ui": {}, "detection": {}, "logging": {}})
    page = window.page_by_key["personalization"]

    assert window.theme_manager.state.background_image == wallpaper
    assert window.theme_manager.state.background_position == "bottom-left"
    assert window.overlay_pet is not None
    assert window.overlay_pet.image_path == pet_image
    assert window.overlay_pet.pet_visible is True
    assert window.overlay_pet.pet_position == "top-right"
    assert window.overlay_pet.pet_size == 144
    assert window.overlay_pet.pet_opacity == 0.6
    assert page.background_image_input.text() == wallpaper
    assert page.wallpaper_size_combo.currentText() == "stretch"
    assert page.pet_visible_box.isChecked()
    assert page.pet_size_box.value() == 144

    assert window.packet_page.shutdown()
    window.close()
    window.deleteLater()
    app.processEvents()
