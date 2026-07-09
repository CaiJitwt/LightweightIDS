from __future__ import annotations

import pytest

from detection.signature_matcher import Signature, SignatureMatcher
from models import PacketRecord


def test_signature_matcher_matches_keyword_across_packet_fields():
    matcher = SignatureMatcher(
        [
            Signature(
                id="SIG_TEST_SQLI",
                name="SQLi keyword",
                category="sql_injection",
                severity="CRITICAL",
                match_type="keyword",
                pattern="union select",
            )
        ]
    )
    packet = PacketRecord(protocol="HTTP", http_path="/search?q=1 UNION SELECT password")

    matches = matcher.match_packet(packet)

    assert len(matches) == 1
    assert matches[0].signature.id == "SIG_TEST_SQLI"
    assert matches[0].field == "http_path"


def test_signature_matcher_matches_regex_in_dns_query():
    matcher = SignatureMatcher(
        [
            Signature(
                id="SIG_TEST_C2",
                name="C2 beacon keyword",
                category="trojan_c2_beacon_keyword",
                severity="HIGH",
                match_type="regex",
                pattern=r"\b(beacon|c2 heartbeat)\b",
            )
        ]
    )
    packet = PacketRecord(protocol="DNS", dns_query="beacon.example.test")

    matches = matcher.match_packet(packet)

    assert len(matches) == 1
    assert matches[0].matched_text == "beacon"


def test_signature_matcher_loads_default_yaml():
    matcher = SignatureMatcher.from_yaml()
    categories = {signature.category for signature in matcher.signatures}

    assert {
        "sql_injection",
        "xss",
        "http_suspicious_path",
        "malicious_command",
        "webshell_indicator",
        "trojan_c2_beacon_keyword",
        "suspicious_user_agent",
    } <= categories


def test_signature_rejects_unknown_match_type():
    with pytest.raises(ValueError, match="unsupported match_type"):
        Signature(
            id="SIG_BAD",
            name="Bad signature",
            category="test",
            severity="LOW",
            match_type="contains",
            pattern="test",
        )
