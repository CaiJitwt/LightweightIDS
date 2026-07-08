from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from storage.migrations import DEFAULT_RULES, SCHEMA_SQL


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = Path.cwd() / self.path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA_SQL)
            self._seed_rules(connection)
            self._seed_default_settings(connection)
            connection.commit()

    def _seed_rules(self, connection: sqlite3.Connection) -> None:
        connection.executemany(
            """
            INSERT INTO rules
                (id, name, category, severity, enabled, threshold, time_window, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                category = excluded.category,
                severity = excluded.severity,
                description = excluded.description
            """,
            DEFAULT_RULES,
        )

    def _seed_default_settings(self, connection: sqlite3.Connection) -> None:
        settings: Iterable[tuple[str, str]] = (
            ("database_path", str(self.path)),
            ("default_pcap_path", ""),
            ("auto_save_packets", "true"),
            ("enable_realtime_detection", "true"),
            ("alert_cooldown_seconds", "10"),
            ("log_level", "INFO"),
        )
        connection.executemany(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            settings,
        )
