from __future__ import annotations

from models import BlocklistEntry
from storage.database import Database


class BlocklistEntryRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, entry: BlocklistEntry) -> BlocklistEntry:
        with self.database.connect() as connection:
            existing = connection.execute(
                """
                SELECT id FROM blocklist_entries
                WHERE kind = ? AND value = ? AND field = ? AND protocol = ?
                """,
                (entry.kind, entry.value, entry.field, entry.protocol),
            ).fetchone()
            if existing:
                entry.id = int(existing["id"])
                connection.execute(
                    """
                    UPDATE blocklist_entries
                    SET enabled = 1, enforcement_status = 'Pending', enforcement_error = '',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (entry.id,),
                )
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO blocklist_entries
                        (kind, value, field, protocol, enabled, enforcement_status, enforcement_error)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.kind,
                        entry.value,
                        entry.field,
                        entry.protocol,
                        1 if entry.enabled else 0,
                        entry.enforcement_status,
                        entry.enforcement_error,
                    ),
                )
                entry.id = int(cursor.lastrowid)
        return entry

    def list_all(self, enabled_only: bool = False) -> list[BlocklistEntry]:
        sql = """
            SELECT id, kind, value, field, protocol, enabled, enforcement_status,
                   enforcement_error, created_at, updated_at
            FROM blocklist_entries
        """
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id DESC"
        with self.database.connect() as connection:
            rows = connection.execute(sql).fetchall()
        return [self._from_row(row) for row in rows]

    def get(self, entry_id: int) -> BlocklistEntry | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT id, kind, value, field, protocol, enabled, enforcement_status,
                       enforcement_error, created_at, updated_at
                FROM blocklist_entries WHERE id = ?
                """,
                (entry_id,),
            ).fetchone()
        return None if row is None else self._from_row(row)

    def update_enforcement(self, entry_id: int, status: str, error: str = "") -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE blocklist_entries
                SET enforcement_status = ?, enforcement_error = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, error, entry_id),
            )

    def delete(self, entry_id: int) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM blocklist_entries WHERE id = ?", (entry_id,))
        return cursor.rowcount > 0

    def _from_row(self, row: object) -> BlocklistEntry:
        return BlocklistEntry(
            id=row["id"],  # type: ignore[index]
            kind=row["kind"],  # type: ignore[index]
            value=row["value"],  # type: ignore[index]
            field=row["field"],  # type: ignore[index]
            protocol=row["protocol"],  # type: ignore[index]
            enabled=bool(row["enabled"]),  # type: ignore[index]
            enforcement_status=row["enforcement_status"],  # type: ignore[index]
            enforcement_error=row["enforcement_error"],  # type: ignore[index]
            created_at=row["created_at"],  # type: ignore[index]
            updated_at=row["updated_at"],  # type: ignore[index]
        )

