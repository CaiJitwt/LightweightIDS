from __future__ import annotations

from storage.database import Database
from storage.repositories import RuleRepository


def test_database_initializes_default_tables_and_rules(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()

    rules = RuleRepository(database).list_all()
    assert {rule.id for rule in rules} >= {
        "PORT_SCAN",
        "SYN_FLOOD",
        "ICMP_FLOOD",
        "SENSITIVE_PORT",
        "BLACKLIST_IP",
    }
