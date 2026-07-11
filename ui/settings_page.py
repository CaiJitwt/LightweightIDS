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


class SettingsPage(QWidget):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config
        self.settings_repository = SettingsRepository(database)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setLabelAlignment(form.labelAlignment())

        self.database_path = QLineEdit(str(database.path))
        self.pcap_path = QLineEdit(
            self.settings_repository.get(
                "default_pcap_path",
                str(config.get("settings", {}).get("default_pcap_path", "")),
            )
        )
        self.pcap_path.setReadOnly(True)
        self.pcap_path.setPlaceholderText("Choose a default pcap file")
        for field in [self.database_path, self.pcap_path]:
            field.setMinimumWidth(420)
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            field.setToolTip(field.text())

        self.browse_pcap_button = QPushButton("Browse")
        self.clear_pcap_button = QPushButton("Clear")
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

        form.addRow("Database path", self.database_path)
        form.addRow("Default pcap path", pcap_row)
        form.addRow("Auto-save packets", self.auto_save_check)
        form.addRow("Enable live detection", self.realtime_check)
        form.addRow("Alert cooldown", self.cooldown_box)
        form.addRow("Log level", self.log_level_combo)

        self.status_label = QLabel("")
        self.status_label.setObjectName("PageHint")
        self.status_label.setWordWrap(True)

        layout.addLayout(form)
        layout.addWidget(self.status_label)
        layout.addStretch()

        self.browse_pcap_button.clicked.connect(self.choose_default_pcap)
        self.clear_pcap_button.clicked.connect(self.clear_default_pcap)
        self.auto_save_check.toggled.connect(self.save_runtime_settings)
        self.realtime_check.toggled.connect(self.save_runtime_settings)
        self.cooldown_box.valueChanged.connect(self.save_runtime_settings)
        self.log_level_combo.currentTextChanged.connect(self.save_runtime_settings)

    def choose_default_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose default pcap file",
            "",
            "pcap files (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if not path:
            return
        self.pcap_path.setText(path)
        self.pcap_path.setToolTip(path)
        self.settings_repository.set("default_pcap_path", path)
        self.status_label.setText("Default pcap path saved.")

    def clear_default_pcap(self) -> None:
        self.pcap_path.clear()
        self.pcap_path.setToolTip("")
        self.settings_repository.set("default_pcap_path", "")
        self.status_label.setText("Default pcap path cleared.")

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
        self.status_label.setText("Settings saved. Capture options apply to the next import or live capture.")
