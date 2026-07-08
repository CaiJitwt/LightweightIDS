from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLineEdit, QSizePolicy, QSpinBox, QVBoxLayout, QWidget

from storage.database import Database


class SettingsPage(QWidget):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setLabelAlignment(form.labelAlignment())

        database_path = QLineEdit(str(database.path))
        pcap_path = QLineEdit("")
        for field in [database_path, pcap_path]:
            field.setMinimumWidth(420)
            field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            field.setToolTip(field.text())

        auto_save = QCheckBox()
        auto_save.setChecked(True)
        realtime = QCheckBox()
        realtime.setChecked(True)
        cooldown = QSpinBox()
        cooldown.setRange(0, 3600)
        cooldown.setSuffix(" s")
        cooldown.setValue(int(config.get("detection", {}).get("alert_cooldown_seconds", 10)))
        log_level = QComboBox()
        log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        configured_log_level = str(config.get("logging", {}).get("level", "INFO")).upper()
        log_level.setCurrentText(configured_log_level if configured_log_level in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "INFO")

        form.addRow("Database path", database_path)
        form.addRow("Default pcap path", pcap_path)
        form.addRow("Auto-save packets", auto_save)
        form.addRow("Enable live detection", realtime)
        form.addRow("Alert cooldown", cooldown)
        form.addRow("Log level", log_level)

        layout.addLayout(form)
        layout.addStretch()
