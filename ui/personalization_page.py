from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ui.theme_manager import ThemeManager
from ui.widgets.overlay_pet_widget import OverlayPetWidget


class PersonalizationPage(QWidget):
    def __init__(self, theme_manager: ThemeManager, overlay_pet: OverlayPetWidget) -> None:
        super().__init__()
        self.theme_manager = theme_manager
        self.overlay_pet = overlay_pet

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        hint = QLabel("Customize the workspace background and optional overlay pet.")
        hint.setObjectName("PageHint")
        hint.setWordWrap(True)

        wallpaper_title = QLabel("Wallpaper")
        wallpaper_title.setObjectName("SectionTitle")
        wallpaper_form = QFormLayout()
        wallpaper_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.background_color_input = QLineEdit(self.theme_manager.state.background_color)
        self.background_color_input.setPlaceholderText("#f6f7f9")
        self.background_image_input = QLineEdit()
        self.background_image_input.setReadOnly(True)
        self.background_image_input.setPlaceholderText("No image selected")
        self.background_image_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.wallpaper_position_combo = QComboBox()
        self.wallpaper_position_combo.addItems(["center", "top-left", "top-right", "bottom-left", "bottom-right"])
        self.wallpaper_size_combo = QComboBox()
        self.wallpaper_size_combo.addItems(["cover", "contain", "stretch", "original"])
        self.wallpaper_opacity_slider = QSlider(Qt.Horizontal)
        self.wallpaper_opacity_slider.setRange(10, 100)
        self.wallpaper_opacity_slider.setValue(100)
        self.wallpaper_opacity_label = QLabel("100%")

        color_row = QHBoxLayout()
        self.apply_color_button = QPushButton("Apply color")
        color_row.addWidget(self.background_color_input, 1)
        color_row.addWidget(self.apply_color_button)

        image_row = QHBoxLayout()
        self.browse_background_button = QPushButton("Choose image")
        self.clear_background_button = QPushButton("Clear")
        image_row.addWidget(self.background_image_input, 1)
        image_row.addWidget(self.browse_background_button)
        image_row.addWidget(self.clear_background_button)

        wallpaper_opacity_row = QHBoxLayout()
        wallpaper_opacity_row.addWidget(self.wallpaper_opacity_slider, 1)
        wallpaper_opacity_row.addWidget(self.wallpaper_opacity_label)

        wallpaper_form.addRow("Background color", color_row)
        wallpaper_form.addRow("Background image", image_row)
        wallpaper_form.addRow("Image position", self.wallpaper_position_combo)
        wallpaper_form.addRow("Image size", self.wallpaper_size_combo)
        wallpaper_form.addRow("Image opacity", wallpaper_opacity_row)

        pet_title = QLabel("Overlay pet")
        pet_title.setObjectName("SectionTitle")
        pet_form = QFormLayout()
        pet_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.pet_image_input = QLineEdit()
        self.pet_image_input.setReadOnly(True)
        self.pet_image_input.setPlaceholderText("No transparent PNG selected")
        self.pet_visible_box = QCheckBox("Show overlay pet")
        self.pet_visible_box.setEnabled(False)
        self.pet_position_combo = QComboBox()
        self.pet_position_combo.addItems(["bottom-right", "bottom-left", "top-right", "top-left"])
        self.pet_size_box = QSpinBox()
        self.pet_size_box.setRange(32, 320)
        self.pet_size_box.setSuffix(" px")
        self.pet_size_box.setValue(120)
        self.pet_opacity_slider = QSlider(Qt.Horizontal)
        self.pet_opacity_slider.setRange(10, 100)
        self.pet_opacity_slider.setValue(100)
        self.pet_opacity_label = QLabel("100%")

        pet_image_row = QHBoxLayout()
        self.browse_pet_button = QPushButton("Choose image")
        self.clear_pet_button = QPushButton("Clear")
        pet_image_row.addWidget(self.pet_image_input, 1)
        pet_image_row.addWidget(self.browse_pet_button)
        pet_image_row.addWidget(self.clear_pet_button)

        opacity_row = QHBoxLayout()
        opacity_row.addWidget(self.pet_opacity_slider, 1)
        opacity_row.addWidget(self.pet_opacity_label)

        pet_form.addRow("Pet image", pet_image_row)
        pet_form.addRow("Visibility", self.pet_visible_box)
        pet_form.addRow("Position", self.pet_position_combo)
        pet_form.addRow("Size", self.pet_size_box)
        pet_form.addRow("Opacity", opacity_row)

        layout.addWidget(hint)
        layout.addWidget(wallpaper_title)
        layout.addLayout(wallpaper_form)
        layout.addSpacing(8)
        layout.addWidget(pet_title)
        layout.addLayout(pet_form)
        layout.addStretch()

        self.apply_color_button.clicked.connect(self.apply_background_color)
        self.browse_background_button.clicked.connect(self.choose_background_image)
        self.clear_background_button.clicked.connect(self.clear_background)
        self.wallpaper_position_combo.currentTextChanged.connect(self.theme_manager.set_background_position)
        self.wallpaper_size_combo.currentTextChanged.connect(self.theme_manager.set_background_size)
        self.wallpaper_opacity_slider.valueChanged.connect(self.update_wallpaper_opacity)
        self.browse_pet_button.clicked.connect(self.choose_pet_image)
        self.clear_pet_button.clicked.connect(self.clear_pet)
        self.pet_visible_box.toggled.connect(self.overlay_pet.set_pet_visible)
        self.pet_position_combo.currentTextChanged.connect(self.overlay_pet.set_pet_position)
        self.pet_size_box.valueChanged.connect(self.overlay_pet.set_pet_size)
        self.pet_opacity_slider.valueChanged.connect(self.update_pet_opacity)

    def apply_background_color(self) -> None:
        self.theme_manager.set_background_color(self.background_color_input.text().strip() or "#f6f7f9")
        self.background_image_input.clear()

    def choose_background_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose background image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp);;All files (*)",
        )
        if not path:
            return
        self.background_image_input.setText(path)
        self.theme_manager.set_background_image(path)
        self.theme_manager.set_background_position(self.wallpaper_position_combo.currentText())
        self.theme_manager.set_background_size(self.wallpaper_size_combo.currentText())
        self.theme_manager.set_background_opacity(self.wallpaper_opacity_slider.value() / 100)

    def clear_background(self) -> None:
        self.theme_manager.clear_background()
        self.background_color_input.setText(self.theme_manager.state.background_color)
        self.background_image_input.clear()

    def update_wallpaper_opacity(self, value: int) -> None:
        self.wallpaper_opacity_label.setText(f"{value}%")
        self.theme_manager.set_background_opacity(value / 100)

    def choose_pet_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose overlay pet image",
            "",
            "PNG images (*.png);;Images (*.png *.gif *.jpg *.jpeg *.bmp);;All files (*)",
        )
        if not path:
            return
        self.pet_image_input.setText(path)
        self.overlay_pet.set_pet_image(path)
        self.overlay_pet.set_pet_position(self.pet_position_combo.currentText())
        self.overlay_pet.set_pet_size(self.pet_size_box.value())
        self.overlay_pet.set_pet_opacity(self.pet_opacity_slider.value() / 100)
        self.pet_visible_box.setEnabled(True)
        self.pet_visible_box.setChecked(True)

    def clear_pet(self) -> None:
        self.pet_image_input.clear()
        self.pet_visible_box.setChecked(False)
        self.pet_visible_box.setEnabled(False)
        self.overlay_pet.clear_pet()

    def update_pet_opacity(self, value: int) -> None:
        self.pet_opacity_label.setText(f"{value}%")
        self.overlay_pet.set_pet_opacity(value / 100)
