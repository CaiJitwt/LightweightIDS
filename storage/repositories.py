from __future__ import annotations

import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from models import AlertRecord, BaselineRecord, CustomRuleRecord, PacketRecord, RuleRecord
from storage.database import Database
from storage.migrations import DEFAULT_RULES


def _insert_record_batch(connection: sqlite3.Connection, table: str, records: list[object]) -> int:
    if not records:
        return 0
    rows = []
    for record in records:
        data = asdict(record)  # type: ignore[arg-type]
        data.pop("id", None)
        rows.append(data)
    columns = ", ".join(rows[0].keys())
    placeholders = ", ".join("?" for _ in rows[0])
    values = [tuple(row.values()) for row in rows]
    connection.executemany(
        f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
        values,
    )
    return len(rows)


class SettingsRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def get(self, key: str, default: str = "") -> str:
        with self.database.connect() as connection:
            row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return str(row["value"])

    def set(self, key: str, value: str) -> None:
        self.set_many({key: value})

    def set_many(self, values: dict[str, str]) -> None:
        if not values:
            return
        with self.database.connect() as connection:
            connection.executemany(
                """
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                values.items(),
            )
            connection.commit()

    def get_bool(self, key: str, default: bool = False) -> bool:
        fallback = "true" if default else "false"
        return self.get(key, fallback).strip().lower() in {"1", "true", "yes", "on"}

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, str(default)).strip())
        except ValueError:
            return default


class TrafficRepository:
    """Persists one capture batch in a single SQLite transaction."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def add_batch(self, packets: list[PacketRecord], alerts: list[AlertRecord]) -> tuple[int, int]:
        if not packets and not alerts:
            return 0, 0
        with self.database.connect() as connection:
            packet_count = _insert_record_batch(connection, "packets", packets)
            alert_count = _insert_record_batch(connection, "alerts", alerts)
            connection.commit()
        return packet_count, alert_count


class PacketRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, packet: PacketRecord) -> int:
        data = asdict(packet)
        data.pop("id", None)
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        with self.database.connect() as connection:
            cursor = connection.execute(f"INSERT INTO packets ({columns}) VALUES ({placeholders})", tuple(data.values()))
            connection.commit()
            return int(cursor.lastrowid)

    def add_many(self, packets: list[PacketRecord]) -> int:
        if not packets:
            return 0
        with self.database.connect() as connection:
            inserted = _insert_record_batch(connection, "packets", packets)
            connection.commit()
        return inserted

    def list_recent(self, limit: int = 10_000) -> list[PacketRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length,
                       tcp_flags, dns_query, http_method, http_host, http_path, raw_summary
                FROM packets
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._from_row(row) for row in reversed(rows)]

    def count(self) -> int:
        with self.database.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0])

    def find_matching_alert(self, alert: AlertRecord) -> PacketRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length,
                       tcp_flags, dns_query, http_method, http_host, http_path, raw_summary
                FROM packets
                WHERE timestamp = ?
                  AND src_ip IS ?
                  AND dst_ip IS ?
                  AND src_port IS ?
                  AND dst_port IS ?
                  AND protocol IS ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    alert.timestamp,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.src_port,
                    alert.dst_port,
                    alert.protocol,
                ),
            ).fetchone()
        return None if row is None else self._from_row(row)

    def list_related_to_alert(self, alert: AlertRecord, limit: int = 500) -> list[PacketRecord]:
        try:
            end_time = datetime.fromisoformat(alert.timestamp)
        except ValueError:
            packet = self.find_matching_alert(alert)
            return [packet] if packet else []

        with self.database.connect() as connection:
            rule_row = connection.execute(
                "SELECT time_window FROM rules WHERE id = ?",
                (alert.rule_id,),
            ).fetchone()
            window_seconds = max(1, int(rule_row["time_window"]) if rule_row else 1)
            start_time = end_time - timedelta(seconds=window_seconds)
            clauses = ["timestamp BETWEEN ? AND ?"]
            values: list[object] = [
                start_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            ]
            if alert.src_ip:
                clauses.append("src_ip = ?")
                values.append(alert.src_ip)

            source_only_rules = {"HOST_SCAN", "LATERAL_MOVEMENT", "DNS_ANOMALY", "ABNORMAL_OUTBOUND"}
            if alert.rule_id not in source_only_rules and alert.dst_ip:
                clauses.append("dst_ip = ?")
                values.append(alert.dst_ip)
            if alert.rule_id == "BRUTE_FORCE" and alert.dst_port is not None:
                clauses.append("dst_port = ?")
                values.append(alert.dst_port)
            if alert.rule_id not in source_only_rules | {"PORT_SCAN", "SYN_FLOOD", "ICMP_FLOOD", "BRUTE_FORCE"}:
                if alert.src_port is not None:
                    clauses.append("src_port = ?")
                    values.append(alert.src_port)
                if alert.dst_port is not None:
                    clauses.append("dst_port = ?")
                    values.append(alert.dst_port)
                if alert.protocol:
                    clauses.append("protocol = ?")
                    values.append(alert.protocol)

            values.append(limit)
            rows = connection.execute(
                f"""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length,
                       tcp_flags, dns_query, http_method, http_host, http_path, raw_summary
                FROM packets
                WHERE {' AND '.join(clauses)}
                ORDER BY timestamp, id
                LIMIT ?
                """,
                tuple(values),
            ).fetchall()
        packets = [self._from_row(row) for row in rows]
        if packets:
            return packets
        packet = self.find_matching_alert(alert)
        return [packet] if packet else []

    def protocol_distribution(self) -> dict[str, int]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT protocol, COUNT(*) AS total FROM packets GROUP BY protocol ORDER BY total DESC"
            ).fetchall()
        return {str(row["protocol"]): int(row["total"]) for row in rows}

    def top_src_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT src_ip, COUNT(*) AS total
                FROM packets
                WHERE src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY total DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [(str(row["src_ip"]), int(row["total"])) for row in rows]

    def top_dst_ports(self, limit: int = 10) -> list[tuple[int, int]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT dst_port, COUNT(*) AS total
                FROM packets
                WHERE dst_port IS NOT NULL
                GROUP BY dst_port
                ORDER BY total DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [(int(row["dst_port"]), int(row["total"])) for row in rows]

    def _from_row(self, row: object) -> PacketRecord:
        return PacketRecord(
            id=row["id"],  # type: ignore[index]
            timestamp=row["timestamp"],  # type: ignore[index]
            src_ip=row["src_ip"],  # type: ignore[index]
            dst_ip=row["dst_ip"],  # type: ignore[index]
            src_port=row["src_port"],  # type: ignore[index]
            dst_port=row["dst_port"],  # type: ignore[index]
            protocol=row["protocol"],  # type: ignore[index]
            length=int(row["length"]),  # type: ignore[index]
            tcp_flags=row["tcp_flags"],  # type: ignore[index]
            dns_query=row["dns_query"],  # type: ignore[index]
            http_method=row["http_method"],  # type: ignore[index]
            http_host=row["http_host"],  # type: ignore[index]
            http_path=row["http_path"],  # type: ignore[index]
            raw_summary=row["raw_summary"],  # type: ignore[index]
        )


class AlertRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, alert: AlertRecord) -> int:
        data = asdict(alert)
        data.pop("id", None)
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        with self.database.connect() as connection:
            cursor = connection.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", tuple(data.values()))
            connection.commit()
            return int(cursor.lastrowid)

    def add_many(self, alerts: list[AlertRecord]) -> int:
        if not alerts:
            return 0
        with self.database.connect() as connection:
            inserted = _insert_record_batch(connection, "alerts", alerts)
            connection.commit()
        return inserted

    def list_all(self, severity: str | None = None, keyword: str | None = None, limit: int = 10_000) -> list[AlertRecord]:
        sql = """
            SELECT id, timestamp, rule_id, rule_name, alert_type, severity, src_ip, dst_ip,
                   src_port, dst_port, protocol, description, evidence, status
            FROM alerts
        """
        clauses: list[str] = []
        values: list[object] = []
        if severity and severity != "All severities":
            clauses.append("severity = ?")
            values.append(severity)
        if keyword:
            like_value = f"%{keyword}%"
            clauses.append(
                """
                (rule_name LIKE ? OR alert_type LIKE ? OR severity LIKE ? OR
                 src_ip LIKE ? OR dst_ip LIKE ? OR description LIKE ? OR evidence LIKE ?)
                """
            )
            values.extend([like_value] * 7)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        values.append(limit)
        with self.database.connect() as connection:
            rows = connection.execute(sql, tuple(values)).fetchall()
        return [self._from_row(row) for row in rows]

    def list_for_host(self, host_ip: str, limit: int = 1_000) -> list[AlertRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, rule_id, rule_name, alert_type, severity, src_ip, dst_ip,
                       src_port, dst_port, protocol, description, evidence, status
                FROM alerts
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY id DESC LIMIT ?
                """,
                (host_ip, host_ip, limit),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def update_status(self, alert_id: int, status: str) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            connection.commit()
            return cursor.rowcount > 0

    def delete(self, alert_id: int) -> bool:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            connection.commit()
            return cursor.rowcount > 0

    def count(self) -> int:
        with self.database.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

    def count_by_severity(self) -> dict[str, int]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity ORDER BY total DESC").fetchall()
        return {str(row["severity"]): int(row["total"]) for row in rows}

    def count_by_type(self) -> dict[str, int]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT alert_type, COUNT(*) AS total FROM alerts GROUP BY alert_type ORDER BY total DESC").fetchall()
        return {str(row["alert_type"]): int(row["total"]) for row in rows}

    def count_by_time_bucket(self, bucket: str = "hour", limit: int = 24) -> list[tuple[str, int]]:
        formats = {
            "hour": "%Y-%m-%d %H:00",
            "day": "%Y-%m-%d",
        }
        if bucket not in formats:
            raise ValueError("bucket must be 'hour' or 'day'")

        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT strftime(?, timestamp) AS bucket, COUNT(*) AS total
                FROM alerts
                WHERE timestamp IS NOT NULL AND timestamp != ''
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (formats[bucket], limit),
            ).fetchall()
        return [(str(row["bucket"]), int(row["total"])) for row in reversed(rows) if row["bucket"]]

    def rule_feedback(self) -> dict[str, dict[str, float | int]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    rule_id,
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
                    SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) AS ignored,
                    SUM(CASE WHEN status NOT IN ('confirmed', 'ignored') THEN 1 ELSE 0 END) AS unconfirmed
                FROM alerts
                GROUP BY rule_id
                ORDER BY total DESC
                """
            ).fetchall()

        feedback: dict[str, dict[str, float | int]] = {}
        for row in rows:
            total = int(row["total"])
            confirmed = int(row["confirmed"] or 0)
            ignored = int(row["ignored"] or 0)
            unconfirmed = int(row["unconfirmed"] or 0)
            feedback[str(row["rule_id"])] = {
                "total": total,
                "confirmed": confirmed,
                "ignored": ignored,
                "unconfirmed": unconfirmed,
                "confirmed_ratio": 0.0 if total == 0 else confirmed / total,
                "ignored_ratio": 0.0 if total == 0 else ignored / total,
            }
        return feedback

    def _from_row(self, row: object) -> AlertRecord:
        return AlertRecord(
            id=row["id"],  # type: ignore[index]
            timestamp=row["timestamp"],  # type: ignore[index]
            rule_id=row["rule_id"],  # type: ignore[index]
            rule_name=row["rule_name"],  # type: ignore[index]
            alert_type=row["alert_type"],  # type: ignore[index]
            severity=row["severity"],  # type: ignore[index]
            src_ip=row["src_ip"],  # type: ignore[index]
            dst_ip=row["dst_ip"],  # type: ignore[index]
            src_port=row["src_port"],  # type: ignore[index]
            dst_port=row["dst_port"],  # type: ignore[index]
            protocol=row["protocol"],  # type: ignore[index]
            description=row["description"],  # type: ignore[index]
            evidence=row["evidence"],  # type: ignore[index]
            status=row["status"],  # type: ignore[index]
        )


class RuleRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def list_all(self) -> list[RuleRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, category, severity, enabled, threshold, time_window, description
                FROM rules
                ORDER BY id
                """
            ).fetchall()
        return [
            RuleRecord(
                id=row["id"],
                name=row["name"],
                category=row["category"],
                severity=row["severity"],
                enabled=bool(row["enabled"]),
                threshold=int(row["threshold"]),
                time_window=int(row["time_window"]),
                description=row["description"],
            )
            for row in rows
        ]

    def update_rule(self, rule: RuleRecord) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE rules
                SET name = ?, category = ?, severity = ?, enabled = ?, threshold = ?,
                    time_window = ?, description = ?
                WHERE id = ?
                """,
                (
                    rule.name,
                    rule.category,
                    rule.severity,
                    1 if rule.enabled else 0,
                    rule.threshold,
                    rule.time_window,
                    rule.description,
                    rule.id,
                ),
            )
            connection.commit()

    def reset_defaults(self) -> None:
        with self.database.connect() as connection:
            connection.executemany(
                """
                INSERT INTO rules
                    (id, name, category, severity, enabled, threshold, time_window, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    category = excluded.category,
                    severity = excluded.severity,
                    enabled = excluded.enabled,
                    threshold = excluded.threshold,
                    time_window = excluded.time_window,
                    description = excluded.description
                """,
                DEFAULT_RULES,
            )
            connection.commit()


class CustomRuleRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def list_all(self) -> list[CustomRuleRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, severity, enabled, protocol, src_ip, dst_ip, src_port,
                       dst_port, keyword, description
                FROM custom_rules
                ORDER BY id
                """
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def add(self, rule: CustomRuleRecord) -> int:
        data = asdict(rule)
        data.pop("id", None)
        data["enabled"] = 1 if rule.enabled else 0
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        with self.database.connect() as connection:
            cursor = connection.execute(f"INSERT INTO custom_rules ({columns}) VALUES ({placeholders})", tuple(data.values()))
            connection.commit()
            return int(cursor.lastrowid)

    def update(self, rule: CustomRuleRecord) -> None:
        if rule.id is None:
            self.add(rule)
            return
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE custom_rules
                SET name = ?, severity = ?, enabled = ?, protocol = ?, src_ip = ?, dst_ip = ?,
                    src_port = ?, dst_port = ?, keyword = ?, description = ?
                WHERE id = ?
                """,
                (
                    rule.name,
                    rule.severity,
                    1 if rule.enabled else 0,
                    rule.protocol,
                    rule.src_ip,
                    rule.dst_ip,
                    rule.src_port,
                    rule.dst_port,
                    rule.keyword,
                    rule.description,
                    rule.id,
                ),
            )
            connection.commit()

    def delete(self, rule_id: int) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            connection.commit()

    def _from_row(self, row: object) -> CustomRuleRecord:
        return CustomRuleRecord(
            id=row["id"],  # type: ignore[index]
            name=row["name"],  # type: ignore[index]
            severity=row["severity"],  # type: ignore[index]
            enabled=bool(row["enabled"]),  # type: ignore[index]
            protocol=row["protocol"],  # type: ignore[index]
            src_ip=row["src_ip"],  # type: ignore[index]
            dst_ip=row["dst_ip"],  # type: ignore[index]
            src_port=row["src_port"],  # type: ignore[index]
            dst_port=row["dst_port"],  # type: ignore[index]
            keyword=row["keyword"],  # type: ignore[index]
            description=row["description"],  # type: ignore[index]
        )


class BaselineRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(self, baseline: BaselineRecord) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO baselines
                    (src_ip, updated_at, window_seconds, packet_count, connection_count,
                     unique_dst_ips, unique_dst_ports, avg_packet_length, bytes_per_window,
                     internal_to_external_ratio)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    window_seconds = excluded.window_seconds,
                    packet_count = excluded.packet_count,
                    connection_count = excluded.connection_count,
                    unique_dst_ips = excluded.unique_dst_ips,
                    unique_dst_ports = excluded.unique_dst_ports,
                    avg_packet_length = excluded.avg_packet_length,
                    bytes_per_window = excluded.bytes_per_window,
                    internal_to_external_ratio = excluded.internal_to_external_ratio
                """,
                (
                    baseline.src_ip,
                    baseline.updated_at,
                    baseline.window_seconds,
                    baseline.packet_count,
                    baseline.connection_count,
                    baseline.unique_dst_ips,
                    baseline.unique_dst_ports,
                    baseline.avg_packet_length,
                    baseline.bytes_per_window,
                    baseline.internal_to_external_ratio,
                ),
            )
            connection.commit()

    def upsert_many(self, baselines: list[BaselineRecord]) -> None:
        if not baselines:
            return
        values = [
            (
                baseline.src_ip,
                baseline.updated_at,
                baseline.window_seconds,
                baseline.packet_count,
                baseline.connection_count,
                baseline.unique_dst_ips,
                baseline.unique_dst_ports,
                baseline.avg_packet_length,
                baseline.bytes_per_window,
                baseline.internal_to_external_ratio,
            )
            for baseline in baselines
        ]
        with self.database.connect() as connection:
            connection.executemany(
                """
                INSERT INTO baselines
                    (src_ip, updated_at, window_seconds, packet_count, connection_count,
                     unique_dst_ips, unique_dst_ports, avg_packet_length, bytes_per_window,
                     internal_to_external_ratio)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    window_seconds = excluded.window_seconds,
                    packet_count = excluded.packet_count,
                    connection_count = excluded.connection_count,
                    unique_dst_ips = excluded.unique_dst_ips,
                    unique_dst_ports = excluded.unique_dst_ports,
                    avg_packet_length = excluded.avg_packet_length,
                    bytes_per_window = excluded.bytes_per_window,
                    internal_to_external_ratio = excluded.internal_to_external_ratio
                """,
                values,
            )
            connection.commit()

    def list_all(self, limit: int = 100) -> list[BaselineRecord]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, src_ip, updated_at, window_seconds, packet_count, connection_count,
                       unique_dst_ips, unique_dst_ports, avg_packet_length, bytes_per_window,
                       internal_to_external_ratio
                FROM baselines
                ORDER BY bytes_per_window DESC, packet_count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def _from_row(self, row: object) -> BaselineRecord:
        return BaselineRecord(
            id=row["id"],  # type: ignore[index]
            src_ip=row["src_ip"],  # type: ignore[index]
            updated_at=row["updated_at"],  # type: ignore[index]
            window_seconds=int(row["window_seconds"]),  # type: ignore[index]
            packet_count=int(row["packet_count"]),  # type: ignore[index]
            connection_count=int(row["connection_count"]),  # type: ignore[index]
            unique_dst_ips=int(row["unique_dst_ips"]),  # type: ignore[index]
            unique_dst_ports=int(row["unique_dst_ports"]),  # type: ignore[index]
            avg_packet_length=float(row["avg_packet_length"]),  # type: ignore[index]
            bytes_per_window=int(row["bytes_per_window"]),  # type: ignore[index]
            internal_to_external_ratio=float(row["internal_to_external_ratio"]),  # type: ignore[index]
        )


class BlacklistRepository:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def list_all(self) -> list[str]:
        if not self.path.exists():
            return []
        values: list[str] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                values.append(value)
        return values

    def save_all(self, ips: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cleaned = []
        for ip in ips:
            value = ip.strip()
            if value and value not in cleaned:
                cleaned.append(value)
        content = "# One IP per line. Blank lines and comments are ignored.\n" + "\n".join(cleaned)
        if cleaned:
            content += "\n"
        self.path.write_text(content, encoding="utf-8")
