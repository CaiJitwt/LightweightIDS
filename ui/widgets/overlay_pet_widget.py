from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel, QSizePolicy, QWidget


class OverlayPetWidget(QLabel):
    POSITIONS = {"bottom-right", "bottom-left", "top-right", "top-left"}

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._position = "bottom-right"
        self._pet_size = 120
        self._image_path = ""
        self._visible_requested = False
        self._pixmap = QPixmap()
        self._opacity_effect = QGraphicsOpacityEffect(self)
        self._opacity_effect.setOpacity(1.0)
        self.setGraphicsEffect(self._opacity_effect)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setScaledContents(True)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.resize(self._pet_size, self._pet_size)
        self.setVisible(False)

    def set_pet_image(self, image_path: str) -> None:
        pixmap = QPixmap(str(Path(image_path)))
        self._image_path = str(Path(image_path)) if not pixmap.isNull() else ""
        self._pixmap = pixmap
        self.setPixmap(pixmap)
        if not pixmap.isNull():
            self.resize(self._pet_size, self._pet_size)

    def set_pet_visible(self, visible: bool) -> None:
        self._visible_requested = visible
        self.setVisible(visible and not self._pixmap.isNull())

    def set_pet_position(self, position: str) -> None:
        if position not in self.POSITIONS:
            raise ValueError(f"Unsupported pet position: {position}")
        self._position = position
        self.reposition()

    def set_pet_size(self, size: int) -> None:
        self._pet_size = max(32, min(size, 320))
        self.resize(self._pet_size, self._pet_size)
        self.reposition()

    def set_pet_opacity(self, opacity: float) -> None:
        self._opacity_effect.setOpacity(max(0.1, min(opacity, 1.0)))

    def clear_pet(self) -> None:
        self._image_path = ""
        self._visible_requested = False
        self._pixmap = QPixmap()
        self.clear()
        self.setVisible(False)

    def reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return

        margin = 18
        x = margin if self._position.endswith("left") else parent.width() - self.width() - margin
        y = margin if self._position.startswith("top") else parent.height() - self.height() - margin
        self.move(max(margin, x), max(margin, y))

    @property
    def image_path(self) -> str:
        return self._image_path

    @property
    def pet_position(self) -> str:
        return self._position

    @property
    def pet_size(self) -> int:
        return self._pet_size

    @property
    def pet_opacity(self) -> float:
        return self._opacity_effect.opacity()

    @property
    def pet_visible(self) -> bool:
        return self._visible_requested
