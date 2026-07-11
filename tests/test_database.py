from __future__ import annotations

from storage.database import Database
from storage.repositories import RuleRepository, SettingsRepository


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
        "ABNORMAL_OUTBOUND",
        "LATERAL_MOVEMENT",
        "HOST_SCAN",
        "TLS_FINGERPRINT",
        "ML_ANOMALY",
        "ML_FLOW_ANOMALY",
        "SIGNATURE_MATCH",
        "BASELINE_DEVIATION",
        "BANDWIDTH_SPIKE",
        "SESSION_DURATION_ANOMALY",
    }


def test_database_initialization_keeps_user_rule_tuning(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()

    with database.connect() as connection:
        connection.execute("UPDATE rules SET threshold = 999 WHERE id = 'ML_ANOMALY'")
        connection.commit()

    database.initialize()

    rules = {rule.id: rule for rule in RuleRepository(database).list_all()}
    assert rules["ML_ANOMALY"].threshold == 999


def test_settings_repository_reads_and_updates_values(tmp_path):
    database = Database(tmp_path / "ids.db")
    database.initialize()
    repository = SettingsRepository(database)

    assert repository.get("default_pcap_path") == ""
    assert repository.get("missing_key", "fallback") == "fallback"

    repository.set("default_pcap_path", str(tmp_path / "traffic.pcap"))
    assert repository.get("default_pcap_path") == str(tmp_path / "traffic.pcap")

    repository.set("default_pcap_path", "")
    assert repository.get("default_pcap_path") == ""
