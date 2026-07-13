from __future__ import annotations

from PySide6.QtWidgets import QLabel, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ui.i18n import LocaleManager, locale_manager
from ui.styles import apply_category_style, configure_responsive_table


class ChartWidget(QWidget):
    """Reusable chart table with a title label and three columns (Item, Value, Percent).

    Supports live retranslation when connected to a ``LocaleManager``.
    Callers that already set the title via the owning page's ``retranslate_ui()``
    can continue to do so; the widget's own ``retranslate_ui()`` updates table
    headers and, when a ``title_key`` was supplied, the title label as well.
    """

    def __init__(
        self,
        title: str = "",
        *,
        title_key: str | None = None,
        lm: LocaleManager | None = None,
    ) -> None:
        super().__init__()
        self._lm = lm or locale_manager()
        self._title_key = title_key

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # -- title label --
        display_title = title or (self._lm.tr(title_key) if title_key else "Chart")
        self.title_label = QLabel(display_title)
        self.title_label.setObjectName("SectionTitle")

        # -- data table --
        self.table = QTableWidget(0, 3)
        self._apply_header_labels()
        configure_responsive_table(
            self.table, stretch_columns=(0,), resize_to_contents_columns=(1, 2)
        )
        self.table.setMinimumHeight(120)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(self.title_label)
        layout.addWidget(self.table, 1)

        self._lm.locale_changed.connect(self.retranslate_ui)

    # ------------------------------------------------------------------
    # i18n
    # ------------------------------------------------------------------

    def _apply_header_labels(self) -> None:
        """Set horizontal header labels from the current locale."""
        self.table.setHorizontalHeaderLabels(
            [
                self._lm.tr("widget.chart.column.item"),
                self._lm.tr("widget.chart.column.value"),
                self._lm.tr("widget.chart.column.percent"),
            ]
        )

    def retranslate_ui(self) -> None:
        """Re-apply all translatable strings after a locale change."""
        self._apply_header_labels()
        if self._title_key is not None:
            self.title_label.setText(self._lm.tr(self._title_key))

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def set_data(self, data: dict[str, int] | list[tuple[object, int]]) -> None:
        """Populate the chart table.

        Accepts either a ``dict[str, int]`` or a ``list[tuple[object, int]]``.
        At most 20 rows are displayed.
        """
        if isinstance(data, dict):
            rows = list(data.items())
        else:
            rows = [(str(key), value) for key, value in data]

        rows = rows[:20]
        total = sum(int(value) for _, value in rows)
        self.table.setRowCount(len(rows))
        for row_index, (label, value) in enumerate(rows):
            percent = 0 if total == 0 else int(value) / total * 100
            values = [str(label), str(value), f"{percent:.1f}%"]
            for column_index, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if column_index == 0:
                    apply_category_style(item, text)
                self.table.setItem(row_index, column_index, item)
