from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication, QGraphicsOpacityEffect, QLabel, QWidget

from ui import styles as _styles_module


@dataclass
class ThemeState:
    background_color: str = "#f6f7f9"
    background_image: str = ""
    background_position: str = "center"
    background_size: str = "cover"
    background_opacity: float = 1.0
    overlay_color: str = ""
    mode: str = "light"


class ThemeManager:
    def __init__(self, target: QWidget) -> None:
        self.target = target
        self.state = ThemeState()
        self.background_layer: QLabel | None = None
        self._background_pixmap = QPixmap()
        self._background_opacity_effect: QGraphicsOpacityEffect | None = None

    def attach_background_layer(self, layer: QLabel) -> None:
        self.background_layer = layer
        self._background_opacity_effect = QGraphicsOpacityEffect(layer)
        layer.setGraphicsEffect(self._background_opacity_effect)
        layer.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        layer.lower()
        layer.hide()

    def apply_default(self) -> None:
        style = _styles_module._app_style() + _styles_module._global_text_style() + self._background_style()
        self.target.setStyleSheet(style)
        self.refresh_background_layer()

    def apply_state(self, state: ThemeState) -> None:
        self.state = ThemeState(
            background_color=state.background_color,
            background_image=state.background_image,
            background_position=state.background_position,
            background_size=state.background_size,
            background_opacity=state.background_opacity,
            overlay_color=state.overlay_color,
            mode=state.mode,
        )
        self._background_pixmap = QPixmap(self.state.background_image) if self.state.background_image else QPixmap()
        self.apply_default()

    def set_background_color(self, color: str) -> None:
        self.state.background_color = color
        self.state.background_image = ""
        self._background_pixmap = QPixmap()
        if self.background_layer:
            self.background_layer.hide()
        self.apply_default()

    def set_background_image(self, image_path: str) -> None:
        self.state.background_image = str(Path(image_path))
        self._background_pixmap = QPixmap(self.state.background_image)
        self.apply_default()

    def set_background_position(self, position: str) -> None:
        self.state.background_position = position
        self.refresh_background_layer()

    def set_background_size(self, size: str) -> None:
        self.state.background_size = size
        self.refresh_background_layer()

    def set_background_opacity(self, opacity: float) -> None:
        self.state.background_opacity = max(0.1, min(opacity, 1.0))
        self.refresh_background_layer()

    def set_overlay_color(self, color: str) -> None:
        self.state.overlay_color = color
        self.apply_default()

    def set_mode(self, mode: str) -> None:
        self.state.mode = mode

    def clear_background(self) -> None:
        self.state.background_color = "#f6f7f9"
        self.state.background_image = ""
        self._background_pixmap = QPixmap()
        if self.background_layer:
            self.background_layer.clear()
            self.background_layer.hide()
        self.state.overlay_color = ""
        self.apply_default()

    def refresh_background_layer(self) -> None:
        if self.background_layer is None:
            return
        if self._background_opacity_effect:
            self._background_opacity_effect.setOpacity(self.state.background_opacity)
        if self._background_pixmap.isNull():
            self.background_layer.hide()
            return

        parent = self.background_layer.parentWidget()
        if parent is None:
            return

        self.background_layer.setGeometry(parent.rect())
        self.background_layer.setAlignment(self._alignment())
        if self.state.background_size == "stretch":
            pixmap = self._background_pixmap.scaled(parent.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        elif self.state.background_size == "contain":
            pixmap = self._background_pixmap.scaled(parent.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        elif self.state.background_size == "original":
            pixmap = self._background_pixmap
        else:
            pixmap = self._background_pixmap.scaled(parent.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
        self.background_layer.setPixmap(pixmap)
        self.background_layer.show()
        self.background_layer.lower()

    def _alignment(self) -> Qt.AlignmentFlag:
        positions = {
            "center": Qt.AlignCenter,
            "top-left": Qt.AlignTop | Qt.AlignLeft,
            "top-right": Qt.AlignTop | Qt.AlignRight,
            "bottom-left": Qt.AlignBottom | Qt.AlignLeft,
            "bottom-right": Qt.AlignBottom | Qt.AlignRight,
        }
        return positions.get(self.state.background_position, Qt.AlignCenter)

    def _background_style(self) -> str:
        return f"""
#AppRoot {{
    background: {self.state.background_color};
}}
"""
