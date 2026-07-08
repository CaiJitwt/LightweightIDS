from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QCheckBox, QFormLayout, QLineEdit, QSpinBox, QVBoxLayout, QWidget

from storage.database import Database


class SettingsPage(QWidget):
    def __init__(self, database: Database, config: dict[str, Any]) -> None:
        super().__init__()
        self.database = database
        self.config = config

        layout = QVBoxLayout(self)
        form = QFormLayout()

        database_path = QLineEdit(str(database.path))
        pcap_path = QLineEdit("")
        auto_save = QCheckBox()
        auto_save.setChecked(True)
        realtime = QCheckBox()
        realtime.setChecked(True)
        cooldown = QSpinBox()
        cooldown.setRange(0, 3600)
        cooldown.setValue(int(config.get("detection", {}).get("alert_cooldown_seconds", 10)))
        log_level = QLineEdit(str(config.get("logging", {}).get("level", "INFO")))

        form.addRow("数据库路径", database_path)
        form.addRow("默认 pcap 路径", pcap_path)
        form.addRow("自动保存数据包", auto_save)
        form.addRow("启用实时检测", realtime)
        form.addRow("告警冷却时间", cooldown)
        form.addRow("日志级别", log_level)

        layout.addLayout(form)
        layout.addStretch()
