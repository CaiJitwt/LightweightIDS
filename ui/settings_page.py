from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

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

        self.database_path = QLineEdit(str(database.path))
        self.pcap_path = QLineEdit(str(config.get("settings", {}).get("default_pcap_path", "")))
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

        form.addRow("Database path", self.database_path)
        form.addRow("Default pcap path", pcap_row)
        form.addRow("Auto-save packets", auto_save)
        form.addRow("Enable live detection", realtime)
        form.addRow("Alert cooldown", cooldown)
        form.addRow("Log level", log_level)

        layout.addLayout(form)
        layout.addStretch()

        self.browse_pcap_button.clicked.connect(self.choose_default_pcap)
        self.clear_pcap_button.clicked.connect(self.clear_default_pcap)

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

    def clear_default_pcap(self) -> None:
        self.pcap_path.clear()
        self.pcap_path.setToolTip("")
