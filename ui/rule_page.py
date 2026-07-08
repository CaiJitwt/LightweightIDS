from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.constants import PROJECT_ROOT
from models import RuleRecord
from storage.database import Database
from storage.repositories import BlacklistRepository, RuleRepository


class RulePage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.rule_repository = RuleRepository(database)
        self.blacklist_repository = BlacklistRepository(PROJECT_ROOT / "config" / "blacklist.txt")
        self.current_rules: list[RuleRecord] = []

        layout = QVBoxLayout(self)

        button_bar = QHBoxLayout()
        self.refresh_button = QPushButton("刷新")
        self.save_button = QPushButton("保存规则")
        self.restore_button = QPushButton("恢复默认规则")
        self.save_blacklist_button = QPushButton("保存黑名单")
        button_bar.addWidget(self.refresh_button)
        button_bar.addWidget(self.save_button)
        button_bar.addWidget(self.restore_button)
        button_bar.addWidget(self.save_blacklist_button)
        button_bar.addStretch()

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["ID", "名称", "分类", "等级", "启用", "阈值", "时间窗口", "说明"])
        self.table.horizontalHeader().setStretchLastSection(True)

        self.blacklist_editor = QTextEdit()
        self.blacklist_editor.setPlaceholderText("每行一个 IP，空行会被忽略。")
        self.blacklist_editor.setMaximumHeight(120)

        layout.addLayout(button_bar)
        layout.addWidget(QLabel("检测规则"))
        layout.addWidget(self.table)
        layout.addWidget(QLabel("黑名单 IP"))
        layout.addWidget(self.blacklist_editor)

        self.refresh_button.clicked.connect(self.refresh)
        self.save_button.clicked.connect(self.save_rules)
        self.restore_button.clicked.connect(self.restore_defaults)
        self.save_blacklist_button.clicked.connect(self.save_blacklist)

        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self) -> None:
        self.current_rules = self.rule_repository.list_all()
        self.table.setRowCount(len(self.current_rules))

        for row_index, rule in enumerate(self.current_rules):
            readonly_values = [rule.id, rule.name, rule.category, rule.severity]
            for column_index, value in enumerate(readonly_values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(row_index, column_index, item)

            enabled_box = QCheckBox()
            enabled_box.setChecked(rule.enabled)
            self.table.setCellWidget(row_index, 4, enabled_box)

            threshold_box = QSpinBox()
            threshold_box.setRange(0, 1_000_000)
            threshold_box.setValue(rule.threshold)
            self.table.setCellWidget(row_index, 5, threshold_box)

            window_box = QSpinBox()
            window_box.setRange(0, 86_400)
            window_box.setValue(rule.time_window)
            self.table.setCellWidget(row_index, 6, window_box)

            description_item = QTableWidgetItem(rule.description)
            self.table.setItem(row_index, 7, description_item)

        self.blacklist_editor.setPlainText("\n".join(self.blacklist_repository.list_all()))

    def save_rules(self) -> None:
        for row, original in enumerate(self.current_rules):
            enabled_widget = self.table.cellWidget(row, 4)
            threshold_widget = self.table.cellWidget(row, 5)
            window_widget = self.table.cellWidget(row, 6)
            description_item = self.table.item(row, 7)

            updated = RuleRecord(
                id=original.id,
                name=original.name,
                category=original.category,
                severity=original.severity,
                enabled=enabled_widget.isChecked() if isinstance(enabled_widget, QCheckBox) else original.enabled,
                threshold=threshold_widget.value() if isinstance(threshold_widget, QSpinBox) else original.threshold,
                time_window=window_widget.value() if isinstance(window_widget, QSpinBox) else original.time_window,
                description=description_item.text() if description_item else original.description,
            )
            self.rule_repository.update_rule(updated)

        QMessageBox.information(self, "保存完成", "规则配置已保存，后续导入和实时抓包会使用新配置。")
        self.refresh()

    def restore_defaults(self) -> None:
        self.rule_repository.reset_defaults()
        QMessageBox.information(self, "已恢复", "默认规则已恢复。")
        self.refresh()

    def save_blacklist(self) -> None:
        ips = self.blacklist_editor.toPlainText().splitlines()
        self.blacklist_repository.save_all(ips)
        QMessageBox.information(self, "保存完成", "黑名单 IP 已保存。")
        self.refresh()
