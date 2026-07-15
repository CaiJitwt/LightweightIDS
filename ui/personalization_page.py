from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ui.i18n import locale_manager
from ui.theme_manager import ThemeManager
from ui.personalization_store import PersonalizationStore, PetState
from ui.widgets.overlay_pet_widget import OverlayPetWidget


class PersonalizationPage(QWidget):
    def __init__(
        self,
        theme_manager: ThemeManager,
        overlay_pet: OverlayPetWidget,
        store: PersonalizationStore,
    ) -> None:
        super().__init__()
        self._lm = locale_manager()
        self._retranslating = False
        self.theme_manager = theme_manager
        self.overlay_pet = overlay_pet
        self.store = store
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(300)
        self.save_timer.timeout.connect(self.save_preferences)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        self.hint_label = QLabel(self._lm.tr("page.personalization.hint"))
        self.hint_label.setObjectName("PageHint")
        self.hint_label.setWordWrap(True)

        self.wallpaper_title_label = QLabel(self._lm.tr("page.personalization.wallpaper_title"))
        self.wallpaper_title_label.setObjectName("SectionTitle")
        wallpaper_form = QFormLayout()
        wallpaper_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.background_color_input = QLineEdit(self.theme_manager.state.background_color)
        self.background_color_input.setPlaceholderText(self._lm.tr("page.personalization.default_color"))
        self.background_image_input = QLineEdit(self.theme_manager.state.background_image)
        self.background_image_input.setReadOnly(True)
        self.background_image_input.setPlaceholderText(self._lm.tr("page.personalization.no_image"))
        self.background_image_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.wallpaper_position_combo = QComboBox()
        self.wallpaper_position_combo.addItems(["center", "top-left", "top-right", "bottom-left", "bottom-right"])
        self.wallpaper_position_combo.setCurrentText(self.theme_manager.state.background_position)
        self.wallpaper_size_combo = QComboBox()
        self.wallpaper_size_combo.addItems(["cover", "contain", "stretch", "original"])
        self.wallpaper_size_combo.setCurrentText(self.theme_manager.state.background_size)
        self.wallpaper_opacity_slider = QSlider(Qt.Horizontal)
        self.wallpaper_opacity_slider.setRange(10, 100)
        wallpaper_opacity = round(self.theme_manager.state.background_opacity * 100)
        self.wallpaper_opacity_slider.setValue(wallpaper_opacity)
        self.wallpaper_opacity_label = QLabel(f"{wallpaper_opacity}%")

        color_row = QHBoxLayout()
        self.apply_color_button = QPushButton(self._lm.tr("page.personalization.apply_color"))
        color_row.addWidget(self.background_color_input, 1)
        color_row.addWidget(self.apply_color_button)

        image_row = QHBoxLayout()
        self.browse_background_button = QPushButton(self._lm.tr("page.personalization.choose_image"))
        self.clear_background_button = QPushButton(self._lm.tr("page.personalization.clear"))
        image_row.addWidget(self.background_image_input, 1)
        image_row.addWidget(self.browse_background_button)
        image_row.addWidget(self.clear_background_button)

        wallpaper_opacity_row = QHBoxLayout()
        wallpaper_opacity_row.addWidget(self.wallpaper_opacity_slider, 1)
        wallpaper_opacity_row.addWidget(self.wallpaper_opacity_label)

        self._wallpaper_form_labels = [
            self._lm.tr("page.personalization.background_color"),
            self._lm.tr("page.personalization.background_image"),
            self._lm.tr("page.personalization.image_position"),
            self._lm.tr("page.personalization.image_size"),
            self._lm.tr("page.personalization.image_opacity"),
        ]
        wallpaper_form.addRow(self._wallpaper_form_labels[0], color_row)
        wallpaper_form.addRow(self._wallpaper_form_labels[1], image_row)
        wallpaper_form.addRow(self._wallpaper_form_labels[2], self.wallpaper_position_combo)
        wallpaper_form.addRow(self._wallpaper_form_labels[3], self.wallpaper_size_combo)
        wallpaper_form.addRow(self._wallpaper_form_labels[4], wallpaper_opacity_row)
        self._wallpaper_labels: list[QLabel] = []
        for i in range(wallpaper_form.rowCount()):
            label_item = wallpaper_form.itemAt(i, QFormLayout.LabelRole)
            if label_item and label_item.widget():
                self._wallpaper_labels.append(label_item.widget())

        self.pet_title_label = QLabel(self._lm.tr("page.personalization.pet_title"))
        self.pet_title_label.setObjectName("SectionTitle")
        pet_form = QFormLayout()
        pet_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.pet_image_input = QLineEdit(self.overlay_pet.image_path)
        self.pet_image_input.setReadOnly(True)
        self.pet_image_input.setPlaceholderText(self._lm.tr("page.personalization.no_pet"))
        self.pet_visible_box = QCheckBox(self._lm.tr("page.personalization.show_pet"))
        self.pet_visible_box.setEnabled(bool(self.overlay_pet.image_path))
        self.pet_visible_box.setChecked(self.overlay_pet.pet_visible)
        self.pet_position_combo = QComboBox()
        self.pet_position_combo.addItems(["bottom-right", "bottom-left", "top-right", "top-left"])
        self.pet_position_combo.setCurrentText(self.overlay_pet.pet_position)
        self.pet_size_box = QSpinBox()
        self.pet_size_box.setRange(32, 320)
        self.pet_size_box.setSuffix(" px")
        self.pet_size_box.setValue(self.overlay_pet.pet_size)
        self.pet_opacity_slider = QSlider(Qt.Horizontal)
        self.pet_opacity_slider.setRange(10, 100)
        pet_opacity = round(self.overlay_pet.pet_opacity * 100)
        self.pet_opacity_slider.setValue(pet_opacity)
        self.pet_opacity_label = QLabel(f"{pet_opacity}%")

        pet_image_row = QHBoxLayout()
        self.browse_pet_button = QPushButton(self._lm.tr("page.personalization.choose_image"))
        self.clear_pet_button = QPushButton(self._lm.tr("page.personalization.clear"))
        pet_image_row.addWidget(self.pet_image_input, 1)
        pet_image_row.addWidget(self.browse_pet_button)
        pet_image_row.addWidget(self.clear_pet_button)

        opacity_row = QHBoxLayout()
        opacity_row.addWidget(self.pet_opacity_slider, 1)
        opacity_row.addWidget(self.pet_opacity_label)

        self._pet_form_labels = [
            self._lm.tr("page.personalization.pet_image"),
            self._lm.tr("page.personalization.pet_visibility"),
            self._lm.tr("page.personalization.pet_position"),
            self._lm.tr("page.personalization.pet_size"),
            self._lm.tr("page.personalization.pet_opacity"),
        ]
        pet_form.addRow(self._pet_form_labels[0], pet_image_row)
        pet_form.addRow(self._pet_form_labels[1], self.pet_visible_box)
        pet_form.addRow(self._pet_form_labels[2], self.pet_position_combo)
        pet_form.addRow(self._pet_form_labels[3], self.pet_size_box)
        pet_form.addRow(self._pet_form_labels[4], opacity_row)
        self._pet_labels: list[QLabel] = []
        for i in range(pet_form.rowCount()):
            label_item = pet_form.itemAt(i, QFormLayout.LabelRole)
            if label_item and label_item.widget():
                self._pet_labels.append(label_item.widget())

        self.save_status_label = QLabel(self._lm.tr("page.personalization.auto_save"))
        self.save_status_label.setObjectName("PageHint")

        layout.addWidget(self.hint_label)
        layout.addWidget(self.wallpaper_title_label)
        layout.addLayout(wallpaper_form)
        layout.addSpacing(8)
        layout.addWidget(self.pet_title_label)
        layout.addLayout(pet_form)
        layout.addWidget(self.save_status_label)
        layout.addStretch()

        self.apply_color_button.clicked.connect(self.apply_background_color)
        self.browse_background_button.clicked.connect(self.choose_background_image)
        self.clear_background_button.clicked.connect(self.clear_background)
        self.wallpaper_position_combo.currentTextChanged.connect(self.change_wallpaper_position)
        self.wallpaper_size_combo.currentTextChanged.connect(self.change_wallpaper_size)
        self.wallpaper_opacity_slider.valueChanged.connect(self.update_wallpaper_opacity)
        self.browse_pet_button.clicked.connect(self.choose_pet_image)
        self.clear_pet_button.clicked.connect(self.clear_pet)
        self.pet_visible_box.toggled.connect(self.change_pet_visibility)
        self.pet_position_combo.currentTextChanged.connect(self.change_pet_position)
        self.pet_size_box.valueChanged.connect(self.change_pet_size)
        self.pet_opacity_slider.valueChanged.connect(self.update_pet_opacity)

        self._lm.locale_changed.connect(self.retranslate_ui)

    def retranslate_ui(self) -> None:
        self._retranslating = True

        self.hint_label.setText(self._lm.tr("page.personalization.hint"))
        self.wallpaper_title_label.setText(self._lm.tr("page.personalization.wallpaper_title"))
        self.pet_title_label.setText(self._lm.tr("page.personalization.pet_title"))

        self.apply_color_button.setText(self._lm.tr("page.personalization.apply_color"))
        self.browse_background_button.setText(self._lm.tr("page.personalization.choose_image"))
        self.clear_background_button.setText(self._lm.tr("page.personalization.clear"))
        self.background_image_input.setPlaceholderText(self._lm.tr("page.personalization.no_image"))

        self.browse_pet_button.setText(self._lm.tr("page.personalization.choose_image"))
        self.clear_pet_button.setText(self._lm.tr("page.personalization.clear"))
        self.pet_image_input.setPlaceholderText(self._lm.tr("page.personalization.no_pet"))
        self.pet_visible_box.setText(self._lm.tr("page.personalization.show_pet"))

        labels = [
            self._lm.tr("page.personalization.background_color"),
            self._lm.tr("page.personalization.background_image"),
            self._lm.tr("page.personalization.image_position"),
            self._lm.tr("page.personalization.image_size"),
            self._lm.tr("page.personalization.image_opacity"),
        ]
        for label_widget, text in zip(self._wallpaper_labels, labels):
            label_widget.setText(text)

        pet_labels = [
            self._lm.tr("page.personalization.pet_image"),
            self._lm.tr("page.personalization.pet_visibility"),
            self._lm.tr("page.personalization.pet_position"),
            self._lm.tr("page.personalization.pet_size"),
            self._lm.tr("page.personalization.pet_opacity"),
        ]
        for label_widget, text in zip(self._pet_labels, pet_labels):
            label_widget.setText(text)

        self.save_status_label.setText(self._lm.tr("page.personalization.auto_save"))

        self._retranslating = False

    def apply_background_color(self) -> None:
        previous = self.theme_manager.state.background_image
        self.theme_manager.set_background_color(self.background_color_input.text().strip() or "#f6f7f9")
        self.background_image_input.clear()
        if self.save_preferences():
            self.store.remove_managed_resource(previous)

    def choose_background_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose background image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp);;All files (*)",
        )
        if not path:
            return
        previous = self.theme_manager.state.background_image
        try:
            managed_path = self.store.import_resource(path, "wallpapers")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Image could not be used", str(exc))
            return
        self.background_image_input.setText(managed_path)
        self.theme_manager.set_background_image(managed_path)
        self.theme_manager.set_background_position(self.wallpaper_position_combo.currentText())
        self.theme_manager.set_background_size(self.wallpaper_size_combo.currentText())
        self.theme_manager.set_background_opacity(self.wallpaper_opacity_slider.value() / 100)
        if self.save_preferences() and previous != managed_path:
            self.store.remove_managed_resource(previous)

    def clear_background(self) -> None:
        previous = self.theme_manager.state.background_image
        self.theme_manager.clear_background()
        self.background_color_input.setText(self.theme_manager.state.background_color)
        self.background_image_input.clear()
        if self.save_preferences():
            self.store.remove_managed_resource(previous)

    def update_wallpaper_opacity(self, value: int) -> None:
        self.wallpaper_opacity_label.setText(f"{value}%")
        self.theme_manager.set_background_opacity(value / 100)
        self.schedule_save()

    def choose_pet_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose overlay pet image",
            "",
            "PNG images (*.png);;Images (*.png *.gif *.jpg *.jpeg *.bmp);;All files (*)",
        )
        if not path:
            return
        previous = self.overlay_pet.image_path
        try:
            managed_path = self.store.import_resource(path, "pets")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Image could not be used", str(exc))
            return
        self.pet_image_input.setText(managed_path)
        self.overlay_pet.set_pet_image(managed_path)
        self.overlay_pet.set_pet_position(self.pet_position_combo.currentText())
        self.overlay_pet.set_pet_size(self.pet_size_box.value())
        self.overlay_pet.set_pet_opacity(self.pet_opacity_slider.value() / 100)
        self.pet_visible_box.setEnabled(True)
        self.pet_visible_box.setChecked(True)
        if self.save_preferences() and previous != managed_path:
            self.store.remove_managed_resource(previous)

    def clear_pet(self) -> None:
        previous = self.overlay_pet.image_path
        self.pet_image_input.clear()
        self.pet_visible_box.setChecked(False)
        self.pet_visible_box.setEnabled(False)
        self.overlay_pet.clear_pet()
        if self.save_preferences():
            self.store.remove_managed_resource(previous)

    def update_pet_opacity(self, value: int) -> None:
        self.pet_opacity_label.setText(f"{value}%")
        self.overlay_pet.set_pet_opacity(value / 100)
        self.schedule_save()

    def change_wallpaper_position(self, position: str) -> None:
        self.theme_manager.set_background_position(position)
        self.schedule_save()

    def change_wallpaper_size(self, size: str) -> None:
        self.theme_manager.set_background_size(size)
        self.schedule_save()

    def change_pet_visibility(self, visible: bool) -> None:
        self.overlay_pet.set_pet_visible(visible)
        self.schedule_save()

    def change_pet_position(self, position: str) -> None:
        self.overlay_pet.set_pet_position(position)
        self.schedule_save()

    def change_pet_size(self, size: int) -> None:
        self.overlay_pet.set_pet_size(size)
        self.schedule_save()

    def schedule_save(self) -> None:
        self.save_status_label.setText("Saving preferences...")
        self.save_timer.start()

    def save_preferences(self) -> bool:
        pet = PetState(
            image_path=self.overlay_pet.image_path,
            visible=self.overlay_pet.pet_visible,
            position=self.overlay_pet.pet_position,
            size=self.overlay_pet.pet_size,
            opacity=self.overlay_pet.pet_opacity,
        )
        try:
            self.store.save(self.theme_manager.state, pet)
        except Exception as exc:
            self.save_status_label.setText(f"Preferences could not be saved: {exc}")
            return False
        self.save_status_label.setText("Preferences saved")
        return True
