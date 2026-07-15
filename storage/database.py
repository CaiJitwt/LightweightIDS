from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Iterable

from storage.migrations import DEFAULT_RULES, SCHEMA_SQL


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = Path.cwd() / self.path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = NORMAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA_SQL)
            self._seed_rules(connection)
            self._seed_default_settings(connection)
            self._migrate_rule_defaults(connection)
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
            ("minimum_alert_severity", "LOW"),
            ("security_event_monitor_enabled", "false"),
            ("security_event_poll_seconds", "5"),
            ("llm_base_url", "https://api.openai.com/v1"),
            ("llm_model", "gpt-4.1-mini"),
            ("llm_api_key_protected", ""),
            ("log_level", "INFO"),
        )
        connection.executemany(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            settings,
        )

    def _migrate_rule_defaults(self, connection: sqlite3.Connection) -> None:
        migration_key = "migration_powershell_threshold_v3"
        migrated = connection.execute("SELECT 1 FROM settings WHERE key = ?", (migration_key,)).fetchone()
        if migrated is not None:
            return
        connection.execute(
            "UPDATE rules SET threshold = 3 WHERE id = 'POWERSHELL_SUSPICIOUS' AND threshold = 2"
        )
        connection.execute("INSERT INTO settings (key, value) VALUES (?, 'true')", (migration_key,))
