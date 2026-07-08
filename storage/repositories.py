from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from models import AlertRecord, CustomRuleRecord, PacketRecord, RuleRecord
from storage.database import Database
from storage.migrations import DEFAULT_RULES


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
        rows = []
        for packet in packets:
            data = asdict(packet)
            data.pop("id", None)
            rows.append(data)
        columns = ", ".join(rows[0].keys())
        placeholders = ", ".join("?" for _ in rows[0])
        values = [tuple(row.values()) for row in rows]
        with self.database.connect() as connection:
            connection.executemany(f"INSERT INTO packets ({columns}) VALUES ({placeholders})", values)
            connection.commit()
        return len(rows)

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
        rows = []
        for alert in alerts:
            data = asdict(alert)
            data.pop("id", None)
            rows.append(data)
        columns = ", ".join(rows[0].keys())
        placeholders = ", ".join("?" for _ in rows[0])
        values = [tuple(row.values()) for row in rows]
        with self.database.connect() as connection:
            connection.executemany(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", values)
            connection.commit()
        return len(rows)

    def list_all(self, severity: str | None = None, keyword: str | None = None, limit: int = 10_000) -> list[AlertRecord]:
        sql = """
            SELECT id, timestamp, rule_id, rule_name, alert_type, severity, src_ip, dst_ip,
                   src_port, dst_port, protocol, description, evidence, status
            FROM alerts
        """
        clauses: list[str] = []
        values: list[object] = []
        if severity and severity != "全部等级":
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

    def update_status(self, alert_id: int, status: str) -> None:
        with self.database.connect() as connection:
            connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            connection.commit()

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
        content = "# 每行一个 IP，空行和 # 注释会被忽略。\n" + "\n".join(cleaned)
        if cleaned:
            content += "\n"
        self.path.write_text(content, encoding="utf-8")
