from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from models import AlertRecord, InvestigationRecord
from report.report_generator import ReportGenerator
from storage.analyst_repositories import InvestigationRepository
from storage.database import Database
from ui.styles import apply_severity_style, configure_responsive_table


class InvestigationDialog(QDialog):
    def __init__(
        self,
        record: InvestigationRecord | None = None,
        *,
        host_ip: str = "",
        summary: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.original = record
        self.setWindowTitle("Edit investigation" if record else "New investigation")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.title_input = QLineEdit(record.title if record else (f"Investigate {host_ip}" if host_ip else ""))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Open", "Monitoring", "Closed"])
        self.status_combo.setCurrentText(record.status if record else "Open")
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.priority_combo.setCurrentText(record.priority if record else "MEDIUM")
        self.host_input = QLineEdit((record.host_ip or "") if record else host_ip)
        self.host_input.setPlaceholderText("Optional host IP")
        self.summary_input = QTextEdit(record.summary if record else summary)
        self.notes_input = QTextEdit(record.notes if record else "")
        self.summary_input.setMinimumHeight(80)
        self.notes_input.setMinimumHeight(100)
        form.addRow("Title", self.title_input)
        form.addRow("Status", self.status_combo)
        form.addRow("Priority", self.priority_combo)
        form.addRow("Host IP", self.host_input)
        form.addRow("Summary", self.summary_input)
        form.addRow("Notes", self.notes_input)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def record(self) -> InvestigationRecord:
        return InvestigationRecord(
            id=self.original.id if self.original else None,
            title=self.title_input.text(),
            status=self.status_combo.currentText(),
            priority=self.priority_combo.currentText(),
            host_ip=self.host_input.text().strip() or None,
            summary=self.summary_input.toPlainText().strip(),
            notes=self.notes_input.toPlainText().strip(),
            created_at=self.original.created_at if self.original else "",
            updated_at=self.original.updated_at if self.original else "",
        )

    def accept(self) -> None:
        try:
            self.record()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid investigation", str(exc))
            return
        super().accept()


class InvestigationsPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.repository = InvestigationRepository(database)
        self.report_generator = ReportGenerator()
        self.investigations: list[InvestigationRecord] = []
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.new_button = QPushButton("New")
        self.edit_button = QPushButton("Edit")
        self.delete_button = QPushButton("Delete")
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Open", "Monitoring", "Closed"])
        self.apply_status_button = QPushButton("Apply status")
        self.remove_evidence_button = QPushButton("Remove evidence")
        self.export_button = QPushButton("Export HTML")
        self.refresh_button = QPushButton("Refresh")
        for widget in (
            self.new_button,
            self.edit_button,
            self.delete_button,
            self.status_combo,
            self.apply_status_button,
            self.remove_evidence_button,
            self.export_button,
            self.refresh_button,
        ):
            toolbar.addWidget(widget)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        self.case_table = QTableWidget(0, 6)
        self.case_table.setHorizontalHeaderLabels(["ID", "Priority", "Status", "Title", "Host", "Updated"])
        configure_responsive_table(self.case_table, stretch_columns=(3,), resize_to_contents_columns=(0, 1, 2, 4, 5))
        self.case_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.case_table.setEditTriggers(QTableWidget.NoEditTriggers)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.evidence_table = QTableWidget(0, 7)
        self.evidence_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Rule", "Source", "Destination", "Description", "Evidence"]
        )
        configure_responsive_table(self.evidence_table, stretch_columns=(2, 5, 6), resize_to_contents_columns=(1, 3, 4))
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        detail_layout.addWidget(self.detail_view, 1)
        detail_layout.addWidget(self.evidence_table, 3)
        splitter.addWidget(self.case_table)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self.new_button.clicked.connect(self.new_investigation)
        self.edit_button.clicked.connect(self.edit_investigation)
        self.delete_button.clicked.connect(self.delete_investigation)
        self.apply_status_button.clicked.connect(self.apply_status)
        self.remove_evidence_button.clicked.connect(self.remove_evidence)
        self.export_button.clicked.connect(self.export_html)
        self.refresh_button.clicked.connect(self.refresh)
        self.case_table.itemSelectionChanged.connect(self.render_selected)
        self.case_table.itemDoubleClicked.connect(lambda _item: self.edit_investigation())
        self.refresh()

    def showEvent(self, event: object) -> None:
        self.refresh()
        super().showEvent(event)  # type: ignore[arg-type]

    def refresh(self, selected_id: int | None = None) -> None:
        selected_id = selected_id or (self._selected_investigation().id if self._selected_investigation() else None)
        self.investigations = self.repository.list_all()
        self.case_table.setRowCount(len(self.investigations))
        for row, record in enumerate(self.investigations):
            values = [str(record.id or ""), record.priority, record.status, record.title, record.host_ip or "", record.updated_at]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, record.id)
                if column == 1:
                    apply_severity_style(item, record.priority)
                self.case_table.setItem(row, column, item)
        if selected_id:
            self.select_investigation(selected_id)
        elif self.investigations:
            self.case_table.selectRow(0)
        else:
            self.detail_view.clear()
            self.evidence_table.setRowCount(0)

    def select_investigation(self, investigation_id: int) -> None:
        for row in range(self.case_table.rowCount()):
            item = self.case_table.item(row, 0)
            if item and item.data(Qt.UserRole) == investigation_id:
                self.case_table.selectRow(row)
                self.case_table.scrollToItem(item)
                return

    def new_investigation(self) -> None:
        dialog = InvestigationDialog(parent=self)
        if dialog.exec() == QDialog.Accepted:
            investigation_id = self.repository.add(dialog.record())
            self.refresh(investigation_id)

    def edit_investigation(self) -> None:
        record = self._selected_investigation()
        if record is None:
            QMessageBox.information(self, "No investigation selected", "Please select an investigation first.")
            return
        dialog = InvestigationDialog(record, parent=self)
        if dialog.exec() == QDialog.Accepted:
            self.repository.update(dialog.record())
            self.refresh(record.id)

    def delete_investigation(self) -> None:
        record = self._selected_investigation()
        if record is None or record.id is None:
            return
        answer = QMessageBox.question(
            self,
            "Delete investigation",
            "Delete this investigation and its evidence snapshots?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.repository.delete(record.id)
            self.refresh()

    def apply_status(self) -> None:
        record = self._selected_investigation()
        if record is None:
            return
        record.status = self.status_combo.currentText()
        self.repository.update(record)
        self.refresh(record.id)

    def add_alert(self, alert: AlertRecord) -> None:
        active = self.repository.list_all(active_only=True)
        options = ["Create new investigation..."] + [f"#{record.id} {record.title}" for record in active]
        choice, accepted = QInputDialog.getItem(self, "Add to investigation", "Investigation", options, 0, False)
        if not accepted:
            return
        if choice == options[0]:
            host_ip = alert.src_ip or alert.dst_ip or ""
            dialog = InvestigationDialog(
                host_ip=host_ip,
                summary=f"Review {alert.rule_name} alert at {alert.timestamp}.",
                parent=self,
            )
            dialog.title_input.setText(f"Investigate {alert.rule_name}")
            dialog.priority_combo.setCurrentText(alert.severity)
            if dialog.exec() != QDialog.Accepted:
                return
            investigation_id = self.repository.add(dialog.record())
        else:
            investigation_id = int(choice.split(" ", 1)[0].lstrip("#"))
        self.repository.add_evidence(investigation_id, alert)
        self.refresh(investigation_id)

    def create_for_host(self, host_ip: str, summary: str, alerts: list[AlertRecord]) -> None:
        dialog = InvestigationDialog(host_ip=host_ip, summary=summary, parent=self)
        dialog.priority_combo.setCurrentText("HIGH" if alerts else "MEDIUM")
        if dialog.exec() != QDialog.Accepted:
            return
        investigation_id = self.repository.add(dialog.record())
        for alert in alerts:
            self.repository.add_evidence(investigation_id, alert)
        self.refresh(investigation_id)

    def render_selected(self) -> None:
        record = self._selected_investigation()
        if record is None or record.id is None:
            return
        self.status_combo.setCurrentText(record.status)
        self.detail_view.setPlainText(
            f"Title: {record.title}\nPriority: {record.priority}\nStatus: {record.status}\n"
            f"Host: {record.host_ip or ''}\nCreated: {record.created_at}\nUpdated: {record.updated_at}\n\n"
            f"Summary:\n{record.summary}\n\nNotes:\n{record.notes}"
        )
        evidence = self.repository.list_evidence(record.id)
        self.evidence_table.setRowCount(len(evidence))
        for row, item_record in enumerate(evidence):
            values = [
                item_record.alert_timestamp,
                item_record.severity,
                item_record.rule_name,
                item_record.src_ip or "",
                item_record.dst_ip or "",
                item_record.description,
                item_record.evidence,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, item_record.id)
                if column == 1:
                    apply_severity_style(item, item_record.severity)
                self.evidence_table.setItem(row, column, item)

    def remove_evidence(self) -> None:
        row = self.evidence_table.currentRow()
        item = self.evidence_table.item(row, 0) if row >= 0 else None
        evidence_id = item.data(Qt.UserRole) if item else None
        if evidence_id and self.repository.remove_evidence(int(evidence_id)):
            self.render_selected()

    def export_html(self) -> None:
        record = self._selected_investigation()
        if record is None or record.id is None:
            QMessageBox.information(self, "No investigation selected", "Please select an investigation first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export investigation HTML",
            f"investigation_{record.id}.html",
            "HTML files (*.html);;All files (*)",
        )
        if not path:
            return
        self.report_generator.generate_investigation_html(record, self.repository.list_evidence(record.id), Path(path))
        QMessageBox.information(self, "Export complete", f"Investigation exported to: {path}")

    def _selected_investigation(self) -> InvestigationRecord | None:
        row = self.case_table.currentRow()
        item = self.case_table.item(row, 0) if row >= 0 else None
        investigation_id = item.data(Qt.UserRole) if item else None
        return next((record for record in self.investigations if record.id == investigation_id), None)
