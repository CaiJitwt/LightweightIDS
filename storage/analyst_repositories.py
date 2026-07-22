from __future__ import annotations

from models import (
    AlertRecord,
    AssetRecord,
    HostConnectionSummary,
    HostTimelineEvent,
    InvestigationEvidenceRecord,
    InvestigationRecord,
)
from parser.packet_parser import _sanitize_display_text, _sanitize_payload
from storage.database import Database


class AssetRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def list_all(self, keyword: str = "") -> list[AssetRecord]:
        sql = """
            SELECT ip, display_name, role, importance, notes, created_at, updated_at
            FROM assets
        """
        values: tuple[object, ...] = ()
        if keyword:
            sql += " WHERE ip LIKE ? OR display_name LIKE ? OR role LIKE ? OR notes LIKE ?"
            value = f"%{keyword}%"
            values = (value, value, value, value)
        sql += " ORDER BY importance DESC, ip"
        with self.database.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        return [self._from_row(row) for row in rows]

    def get(self, ip: str) -> AssetRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT ip, display_name, role, importance, notes, created_at, updated_at
                FROM assets WHERE ip = ?
                """,
                (ip,),
            ).fetchone()
        return None if row is None else self._from_row(row)

    def save(self, asset: AssetRecord) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO assets (ip, display_name, role, importance, notes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    display_name = excluded.display_name,
                    role = excluded.role,
                    importance = excluded.importance,
                    notes = excluded.notes,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (asset.ip, asset.display_name, asset.role, asset.importance, asset.notes),
            )

    def delete(self, ip: str) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM assets WHERE ip = ?", (ip,))
        return cursor.rowcount > 0

    def importance_map(self) -> dict[str, int]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT ip, importance FROM assets").fetchall()
        return {str(row["ip"]): int(row["importance"]) for row in rows}

    def _from_row(self, row: object) -> AssetRecord:
        return AssetRecord(
            ip=row["ip"],  # type: ignore[index]
            display_name=row["display_name"],  # type: ignore[index]
            role=row["role"],  # type: ignore[index]
            importance=int(row["importance"]),  # type: ignore[index]
            notes=row["notes"],  # type: ignore[index]
            created_at=row["created_at"],  # type: ignore[index]
            updated_at=row["updated_at"],  # type: ignore[index]
        )


class InvestigationRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def list_all(self, active_only: bool = False) -> list[InvestigationRecord]:
        sql = """
            SELECT id, title, status, priority, host_ip, summary, notes, created_at, updated_at
            FROM investigations
        """
        if active_only:
            sql += " WHERE status != 'Closed'"
        sql += " ORDER BY CASE priority WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC, updated_at DESC"
        with self.database.connect() as connection:
            rows = connection.execute(sql).fetchall()
        return [self._investigation_from_row(row) for row in rows]

    def get(self, investigation_id: int) -> InvestigationRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT id, title, status, priority, host_ip, summary, notes, created_at, updated_at
                FROM investigations WHERE id = ?
                """,
                (investigation_id,),
            ).fetchone()
        return None if row is None else self._investigation_from_row(row)

    def add(self, record: InvestigationRecord) -> int:
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO investigations (title, status, priority, host_ip, summary, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (record.title, record.status, record.priority, record.host_ip, record.summary, record.notes),
            )
            return int(cursor.lastrowid)

    def update(self, record: InvestigationRecord) -> None:
        if record.id is None:
            raise ValueError("Investigation ID is required for update")
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE investigations
                SET title = ?, status = ?, priority = ?, host_ip = ?, summary = ?, notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (record.title, record.status, record.priority, record.host_ip, record.summary, record.notes, record.id),
            )

    def delete(self, investigation_id: int) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        return cursor.rowcount > 0

    def add_evidence(self, investigation_id: int, alert: AlertRecord) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO investigation_evidence
                    (investigation_id, alert_id, alert_timestamp, rule_id, rule_name, severity,
                     src_ip, dst_ip, description, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    alert.id,
                    alert.timestamp,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.description,
                    alert.evidence,
                ),
            )
        return cursor.rowcount > 0

    def list_evidence(self, investigation_id: int) -> list[InvestigationEvidenceRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, investigation_id, alert_id, alert_timestamp, rule_id, rule_name,
                       severity, src_ip, dst_ip, description, evidence, added_at
                FROM investigation_evidence
                WHERE investigation_id = ?
                ORDER BY alert_timestamp, id
                """,
                (investigation_id,),
            ).fetchall()
        return [self._evidence_from_row(row) for row in rows]

    def remove_evidence(self, evidence_id: int) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM investigation_evidence WHERE id = ?", (evidence_id,))
        return cursor.rowcount > 0

    def _investigation_from_row(self, row: object) -> InvestigationRecord:
        return InvestigationRecord(
            id=row["id"],  # type: ignore[index]
            title=row["title"],  # type: ignore[index]
            status=row["status"],  # type: ignore[index]
            priority=row["priority"],  # type: ignore[index]
            host_ip=row["host_ip"],  # type: ignore[index]
            summary=row["summary"],  # type: ignore[index]
            notes=row["notes"],  # type: ignore[index]
            created_at=row["created_at"],  # type: ignore[index]
            updated_at=row["updated_at"],  # type: ignore[index]
        )

    def _evidence_from_row(self, row: object) -> InvestigationEvidenceRecord:
        return InvestigationEvidenceRecord(
            id=row["id"],  # type: ignore[index]
            investigation_id=int(row["investigation_id"]),  # type: ignore[index]
            alert_id=row["alert_id"],  # type: ignore[index]
            alert_timestamp=row["alert_timestamp"],  # type: ignore[index]
            rule_id=row["rule_id"],  # type: ignore[index]
            rule_name=row["rule_name"],  # type: ignore[index]
            severity=row["severity"],  # type: ignore[index]
            src_ip=row["src_ip"],  # type: ignore[index]
            dst_ip=row["dst_ip"],  # type: ignore[index]
            description=row["description"],  # type: ignore[index]
            evidence=row["evidence"],  # type: ignore[index]
            added_at=row["added_at"],  # type: ignore[index]
        )


def _timeline_packet_summary(protocol: str, raw_summary: str) -> str:
    """Build a clean one-liner for host timeline packet events.

    Strips the ``| payload=…`` suffix because for encrypted protocols (TLS,
    HTTPS, QUIC) it is ciphertext noise, and even for cleartext protocols
    the Scapy layer summary already carries the essential information.
    """
    raw = raw_summary
    idx = raw.find(" | payload=")
    if idx != -1:
        raw = raw[:idx]
    return f"{protocol}: {raw}"


class HostRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def packet_activity(self) -> dict[str, dict[str, int | str]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT ip, SUM(total) AS total, SUM(incoming) AS incoming,
                       SUM(outgoing) AS outgoing, MAX(last_seen) AS last_seen
                FROM (
                    SELECT src_ip AS ip, COUNT(*) AS total, 0 AS incoming,
                           COUNT(*) AS outgoing, MAX(timestamp) AS last_seen
                    FROM packets WHERE src_ip IS NOT NULL AND src_ip != '' GROUP BY src_ip
                    UNION ALL
                    SELECT dst_ip AS ip, COUNT(*) AS total, COUNT(*) AS incoming,
                           0 AS outgoing, MAX(timestamp) AS last_seen
                    FROM packets WHERE dst_ip IS NOT NULL AND dst_ip != '' GROUP BY dst_ip
                ) GROUP BY ip
                """
            ).fetchall()
        return {
            str(row["ip"]): {
                "packet_count": int(row["total"]),
                "incoming_packets": int(row["incoming"]),
                "outgoing_packets": int(row["outgoing"]),
                "last_seen": str(row["last_seen"] or ""),
            }
            for row in rows
        }

    def alert_activity(self) -> dict[str, dict[str, int | str]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT ip, SUM(total) AS total, SUM(critical) AS critical, MAX(last_seen) AS last_seen
                FROM (
                    SELECT src_ip AS ip, COUNT(*) AS total,
                           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                           MAX(timestamp) AS last_seen
                    FROM alerts WHERE src_ip IS NOT NULL AND src_ip != '' GROUP BY src_ip
                    UNION ALL
                    SELECT dst_ip AS ip, COUNT(*) AS total,
                           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                           MAX(timestamp) AS last_seen
                    FROM alerts WHERE dst_ip IS NOT NULL AND dst_ip != '' GROUP BY dst_ip
                ) GROUP BY ip
                """
            ).fetchall()
        return {
            str(row["ip"]): {
                "alert_count": int(row["total"]),
                "critical_count": int(row["critical"] or 0),
                "last_seen": str(row["last_seen"] or ""),
            }
            for row in rows
        }

    def connections(self, host_ip: str, limit: int = 200) -> list[HostConnectionSummary]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS peer_ip,
                    CASE WHEN src_ip = ? THEN 'Outbound' ELSE 'Inbound' END AS direction,
                    protocol,
                    dst_port AS port,
                    COUNT(*) AS total,
                    MAX(timestamp) AS last_seen
                FROM packets
                WHERE src_ip = ? OR dst_ip = ?
                GROUP BY peer_ip, direction, protocol, port
                ORDER BY total DESC, last_seen DESC
                LIMIT ?
                """,
                (host_ip, host_ip, host_ip, host_ip, limit),
            ).fetchall()
        return [
            HostConnectionSummary(
                peer_ip=str(row["peer_ip"] or ""),
                direction=str(row["direction"]),
                protocol=str(row["protocol"]),
                port=row["port"],
                packet_count=int(row["total"]),
                last_seen=str(row["last_seen"] or ""),
            )
            for row in rows
        ]

    def protocol_distribution(self, host_ip: str) -> dict[str, int]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT protocol, COUNT(*) AS total FROM packets
                WHERE src_ip = ? OR dst_ip = ? GROUP BY protocol ORDER BY total DESC
                """,
                (host_ip, host_ip),
            ).fetchall()
        return {str(row["protocol"]): int(row["total"]) for row in rows}

    def port_distribution(self, host_ip: str, limit: int = 10) -> list[tuple[int, int]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT dst_port, COUNT(*) AS total FROM packets
                WHERE (src_ip = ? OR dst_ip = ?) AND dst_port IS NOT NULL
                GROUP BY dst_port ORDER BY total DESC LIMIT ?
                """,
                (host_ip, host_ip, limit),
            ).fetchall()
        return [(int(row["dst_port"]), int(row["total"])) for row in rows]

    def timeline(self, host_ip: str, limit: int = 200) -> list[HostTimelineEvent]:
        with self.database.connect() as connection:
            packet_rows = connection.execute(
                """
                SELECT timestamp, src_ip, dst_ip, protocol, raw_summary
                FROM packets WHERE src_ip = ? OR dst_ip = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (host_ip, host_ip, limit),
            ).fetchall()
            alert_rows = connection.execute(
                """
                SELECT timestamp, src_ip, dst_ip, severity, rule_name, description
                FROM alerts WHERE src_ip = ? OR dst_ip = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (host_ip, host_ip, limit),
            ).fetchall()

        events = [
            HostTimelineEvent(
                timestamp=str(row["timestamp"]),
                event_type="Packet",
                direction="Outbound" if row["src_ip"] == host_ip else "Inbound",
                peer_ip=str(row["dst_ip"] if row["src_ip"] == host_ip else row["src_ip"] or ""),
                summary=_sanitize_payload(
                    _timeline_packet_summary(str(row["protocol"]), str(row["raw_summary"] or ""))
                ),
            )
            for row in packet_rows
        ]
        events.extend(
            HostTimelineEvent(
                timestamp=str(row["timestamp"]),
                event_type="Alert",
                direction="Outbound" if row["src_ip"] == host_ip else "Inbound",
                peer_ip=str(row["dst_ip"] if row["src_ip"] == host_ip else row["src_ip"] or ""),
                summary=_sanitize_display_text(f"{row['rule_name']}: {row['description']}"),
                severity=str(row["severity"]),
            )
            for row in alert_rows
        )
        events.sort(key=lambda event: event.timestamp, reverse=True)
        return events[:limit]

