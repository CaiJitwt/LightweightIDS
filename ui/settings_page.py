from __future__ import annotations

import logging
from typing import Any

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
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from storage.database import Database
from storage.repositories import SettingsRepository
from ui.i18n import locale_manager


class SettingsPage(QWidget):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config
        self.settings_repository = SettingsRepository(database)
        self._lm = locale_manager()
        self._retranslating = False
        self._form_label_widgets: list[QLabel] = []

        layout = QVBoxLayout(self)
        self._form = QFormLayout()
        self._form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self._form.setLabelAlignment(self._form.labelAlignment())

        self.database_path = QLineEdit(str(database.path))
        self.database_path.setReadOnly(True)
        self.pcap_path = QLineEdit(
            self.settings_repository.get(
                "default_pcap_path",
                str(config.get("settings", {}).get("default_pcap_path", "")),
            )
        )
        self.pcap_path.setReadOnly(True)
        self.pcap_path.setPlaceholderText(self._lm.tr("page.settings.pcap_placeholder"))
        for field in [self.database_path, self.pcap_path]:
            field.setMinimumWidth(420)
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            field.setToolTip(field.text())

        self.browse_pcap_button = QPushButton(self._lm.tr("page.settings.browse"))
        self.clear_pcap_button = QPushButton(self._lm.tr("page.settings.clear"))
        pcap_row = QHBoxLayout()
        pcap_row.addWidget(self.pcap_path, 1)
        pcap_row.addWidget(self.browse_pcap_button)
        pcap_row.addWidget(self.clear_pcap_button)

        detection_config = config.get("detection", {})
        self.auto_save_check = QCheckBox()
        self.auto_save_check.setChecked(
            self.settings_repository.get_bool(
                "auto_save_packets",
                bool(detection_config.get("auto_save_packets", True)),
            )
        )
        self.realtime_check = QCheckBox()
        self.realtime_check.setChecked(
            self.settings_repository.get_bool(
                "enable_realtime_detection",
                bool(detection_config.get("enable_realtime_detection", True)),
            )
        )
        self.cooldown_box = QSpinBox()
        self.cooldown_box.setRange(0, 3600)
        self.cooldown_box.setSuffix(" s")
        self.cooldown_box.setValue(
            self.settings_repository.get_int(
                "alert_cooldown_seconds",
                int(detection_config.get("alert_cooldown_seconds", 10)),
            )
        )
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        configured_log_level = self.settings_repository.get(
            "log_level",
            str(config.get("logging", {}).get("level", "INFO")),
        ).upper()
        self.log_level_combo.setCurrentText(
            configured_log_level
            if configured_log_level in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
            else "INFO"
        )

        self.language_combo = QComboBox()
        self.language_combo.addItems([
            self._lm.tr("page.settings.lang_en"),
            self._lm.tr("page.settings.lang_zh"),
        ])
        saved_locale = self.settings_repository.get("app_locale", "en")
        self.language_combo.setCurrentIndex(0 if saved_locale == "en" else 1)

        self._form_label_keys: list[str] = [
            "page.settings.database_path",
            "page.settings.default_pcap_path",
            "page.settings.auto_save_packets",
            "page.settings.enable_live_detection",
            "page.settings.alert_cooldown",
            "page.settings.log_level",
            "page.settings.language",
        ]

        self._add_form_rows()

        self.status_label = QLabel("")
        self.status_label.setObjectName("PageHint")
        self.status_label.setWordWrap(True)

        layout.addLayout(self._form)
        layout.addWidget(self.status_label)
        layout.addStretch()

        self.browse_pcap_button.clicked.connect(self.choose_default_pcap)
        self.clear_pcap_button.clicked.connect(self.clear_default_pcap)
        self.auto_save_check.toggled.connect(self.save_runtime_settings)
        self.realtime_check.toggled.connect(self.save_runtime_settings)
        self.cooldown_box.valueChanged.connect(self.save_runtime_settings)
        self.log_level_combo.currentTextChanged.connect(self.save_runtime_settings)
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)

        self._lm.locale_changed.connect(self.retranslate_ui)

    def _add_form_rows(self) -> None:
        widgets = [
            self.database_path,
            self.pcap_row(),
            self.auto_save_check,
            self.realtime_check,
            self.cooldown_box,
            self.log_level_combo,
            self.language_combo,
        ]
        for label_key, widget in zip(self._form_label_keys, widgets):
            label = QLabel(self._lm.tr(label_key))
            self._form.addRow(label, widget)
            self._form_label_widgets.append(label)

    def pcap_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addWidget(self.pcap_path, 1)
        row.addWidget(self.browse_pcap_button)
        row.addWidget(self.clear_pcap_button)
        return row

    def _on_language_changed(self, index: int) -> None:
        if self._retranslating:
            return
        new_locale = "en" if index == 0 else "zh"
        self._lm.set_locale(new_locale)

    def retranslate_ui(self) -> None:
        self._retranslating = True

        self.browse_pcap_button.setText(self._lm.tr("page.settings.browse"))
        self.clear_pcap_button.setText(self._lm.tr("page.settings.clear"))
        self.pcap_path.setPlaceholderText(self._lm.tr("page.settings.pcap_placeholder"))

        for label_widget, label_key in zip(self._form_label_widgets, self._form_label_keys):
            label_widget.setText(self._lm.tr(label_key))

        self.language_combo.setItemText(0, self._lm.tr("page.settings.lang_en"))
        self.language_combo.setItemText(1, self._lm.tr("page.settings.lang_zh"))
        self.language_combo.setCurrentIndex(0 if self._lm.current_locale == "en" else 1)

        self._retranslating = False

    def choose_default_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            self._lm.tr("page.settings.dialog.choose_pcap"),
            "",
            "pcap files (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if not path:
            return
        self.pcap_path.setText(path)
        self.pcap_path.setToolTip(path)
        self.settings_repository.set("default_pcap_path", path)
        self.status_label.setText(self._lm.tr("page.settings.pcap_saved"))

    def clear_default_pcap(self) -> None:
        self.pcap_path.clear()
        self.pcap_path.setToolTip("")
        self.settings_repository.set("default_pcap_path", "")
        self.status_label.setText(self._lm.tr("page.settings.pcap_cleared"))

    def save_runtime_settings(self) -> None:
        log_level = self.log_level_combo.currentText()
        self.settings_repository.set_many(
            {
                "auto_save_packets": "true" if self.auto_save_check.isChecked() else "false",
                "enable_realtime_detection": "true" if self.realtime_check.isChecked() else "false",
                "alert_cooldown_seconds": str(self.cooldown_box.value()),
                "log_level": log_level,
            }
        )
        logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))
        self.status_label.setText(self._lm.tr("page.settings.saved_msg"))
