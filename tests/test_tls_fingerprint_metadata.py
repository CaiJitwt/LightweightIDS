from __future__ import annotations

from detection.rules.tls_fingerprint import TlsFingerprintRule
from detection.tls import extract_tls_metadata, tls_metadata_findings
from models import PacketRecord


def tls_packet(summary: str) -> PacketRecord:
    return PacketRecord(
        timestamp="2026-01-01 00:00:00.000",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=51000,
        dst_port=443,
        protocol="TLS",
        raw_summary=summary,
    )


def test_tls_metadata_extracts_structured_fields():
    metadata = extract_tls_metadata(
        tls_packet(
            "TLS ClientHello version=TLSv1.2 cipher=TLS_AES_128_GCM_SHA256 "
            "self_signed=false expired=false alpn=h2 sni=example.test"
        )
    )

    assert metadata.version == "TLSv1.2"
    assert metadata.cipher == "TLS_AES_128_GCM_SHA256"
    assert metadata.alpn == "h2"
    assert metadata.sni == "example.test"


def test_tls_metadata_findings_detect_certificate_alpn_and_missing_sni():
    findings = tls_metadata_findings(
        tls_packet(
            "TLS ClientHello version=TLSv1.2 cipher=TLS_AES_128_GCM_SHA256 "
            "self_signed=true expired=true alpn=ftp sni="
        )
    )

    assert "self_signed_certificate" in findings
    assert "expired_certificate" in findings
    assert "unusual_alpn=ftp" in findings
    assert "missing_sni" in findings


def test_tls_fingerprint_rule_detects_metadata_risks():
    alerts = TlsFingerprintRule().process(
        tls_packet(
            "TLS ClientHello version=TLSv1.0 cipher=RC4-SHA self_signed=true "
            "expired=true alpn=ftp sni="
        )
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "TLS_WEAK_FINGERPRINT"
    assert "weak_version=TLSv1.0" in alerts[0].evidence
    assert "weak_cipher=RC4-SHA" in alerts[0].evidence
    assert "self_signed_certificate" in alerts[0].evidence
    assert "expired_certificate" in alerts[0].evidence
    assert "unusual_alpn=ftp" in alerts[0].evidence
    assert "missing_sni" in alerts[0].evidence
