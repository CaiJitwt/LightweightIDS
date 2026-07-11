from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from models import AssetRecord
from storage.analyst_repositories import AssetRepository
from storage.database import Database
from ui.styles import configure_responsive_table


class AssetDialog(QDialog):
    def __init__(self, asset: AssetRecord | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.asset = asset
        self.setWindowTitle("Edit asset" if asset else "Add asset")
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.ip_input = QLineEdit(asset.ip if asset else "")
        self.ip_input.setPlaceholderText("192.168.1.10")
        self.ip_input.setReadOnly(asset is not None)
        self.name_input = QLineEdit(asset.display_name if asset else "")
        self.role_combo = QComboBox()
        self.role_combo.addItems(sorted(AssetRecord.VALID_ROLES))
        self.role_combo.setCurrentText(asset.role if asset else "Other")
        self.importance_box = QSpinBox()
        self.importance_box.setRange(0, 100)
        self.importance_box.setValue(asset.importance if asset else 50)
        self.notes_input = QTextEdit(asset.notes if asset else "")
        self.notes_input.setMinimumHeight(90)
        form.addRow("IP address", self.ip_input)
        form.addRow("Display name", self.name_input)
        form.addRow("Role", self.role_combo)
        form.addRow("Importance", self.importance_box)
        form.addRow("Notes", self.notes_input)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def record(self) -> AssetRecord:
        return AssetRecord(
            ip=self.ip_input.text(),
            display_name=self.name_input.text().strip(),
            role=self.role_combo.currentText(),
            importance=self.importance_box.value(),
            notes=self.notes_input.toPlainText().strip(),
            created_at=self.asset.created_at if self.asset else "",
            updated_at=self.asset.updated_at if self.asset else "",
        )

    def accept(self) -> None:
        try:
            self.record()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid asset", str(exc))
            return
        super().accept()


class AssetsPage(QWidget):
    assets_changed = Signal()

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.repository = AssetRepository(database)
        self.assets: list[AssetRecord] = []
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search IP, name, role or notes")
        self.add_button = QPushButton("Add")
        self.edit_button = QPushButton("Edit")
        self.delete_button = QPushButton("Delete")
        self.refresh_button = QPushButton("Refresh")
        toolbar.addWidget(self.search_input, 1)
        toolbar.addWidget(self.add_button)
        toolbar.addWidget(self.edit_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.refresh_button)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["IP address", "Display name", "Role", "Importance", "Notes", "Updated"])
        configure_responsive_table(self.table, stretch_columns=(1, 4), resize_to_contents_columns=(2, 3, 5))
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addLayout(toolbar)
        layout.addWidget(self.table, 1)
        self.search_input.textChanged.connect(self.refresh)
        self.add_button.clicked.connect(self.add_asset)
        self.edit_button.clicked.connect(self.edit_asset)
        self.delete_button.clicked.connect(self.delete_asset)
        self.refresh_button.clicked.connect(self.refresh)
        self.table.itemDoubleClicked.connect(lambda _item: self.edit_asset())
        self.refresh()

    def refresh(self) -> None:
        self.assets = self.repository.list_all(self.search_input.text().strip())
        self.table.setRowCount(len(self.assets))
        for row, asset in enumerate(self.assets):
            values = [asset.ip, asset.display_name, asset.role, str(asset.importance), asset.notes, asset.updated_at]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, asset.ip)
                self.table.setItem(row, column, item)

    def add_asset(self) -> None:
        dialog = AssetDialog(parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        try:
            self.repository.save(dialog.record())
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", str(exc))
            return
        self.refresh()
        self.assets_changed.emit()

    def edit_asset(self) -> None:
        asset = self._selected_asset()
        if asset is None:
            QMessageBox.information(self, "No asset selected", "Please select an asset first.")
            return
        dialog = AssetDialog(asset, self)
        if dialog.exec() != QDialog.Accepted:
            return
        self.repository.save(dialog.record())
        self.refresh()
        self.assets_changed.emit()

    def delete_asset(self) -> None:
        asset = self._selected_asset()
        if asset is None:
            QMessageBox.information(self, "No asset selected", "Please select an asset first.")
            return
        answer = QMessageBox.question(
            self,
            "Delete asset",
            f"Delete asset metadata for {asset.ip}? Traffic and alerts will be kept.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes and self.repository.delete(asset.ip):
            self.refresh()
            self.assets_changed.emit()

    def _selected_asset(self) -> AssetRecord | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        ip = item.data(Qt.UserRole) if item else None
        return next((asset for asset in self.assets if asset.ip == ip), None)

