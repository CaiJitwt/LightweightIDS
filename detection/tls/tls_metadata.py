from __future__ import annotations

from dataclasses import dataclass
import re

from models import PacketRecord


WEAK_VERSIONS = {"sslv2", "sslv3", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1"}
WEAK_CIPHER_KEYWORDS = ("rc4", "3des", " des ", "export", "null", "md5")
EXPECTED_ALPN = {"h2", "http/1.1", "http/1.0", "http/3", "acme-tls/1"}


@dataclass(frozen=True, slots=True)
class TlsMetadata:
    version: str = ""
    cipher: str = ""
    self_signed: bool = False
    expired: bool = False
    alpn: str = ""
    sni: str = ""
    missing_sni: bool = False


def extract_tls_metadata(packet: PacketRecord) -> TlsMetadata:
    text = packet.raw_summary or ""
    values = {key.lower(): value.strip() for key, value in _extract_key_values(text).items()}
    sni = values.get("sni", values.get("server_name", values.get("servername", "")))
    missing_sni = _truthy(values.get("missing_sni")) or _truthy(values.get("no_sni"))
    if "sni" in values and not sni:
        missing_sni = True

    return TlsMetadata(
        version=values.get("version", values.get("tls_version", "")),
        cipher=values.get("cipher", values.get("cipher_suite", "")),
        self_signed=_truthy(values.get("self_signed")) or _truthy(values.get("cert_self_signed")),
        expired=_truthy(values.get("expired")) or _truthy(values.get("cert_expired")),
        alpn=values.get("alpn", ""),
        sni=sni,
        missing_sni=missing_sni,
    )


def tls_metadata_findings(packet: PacketRecord) -> list[str]:
    metadata = extract_tls_metadata(packet)
    findings: list[str] = []
    version = metadata.version.lower()
    cipher = f" {metadata.cipher.lower()} "
    alpn = metadata.alpn.lower()

    if version in WEAK_VERSIONS:
        findings.append(f"weak_version={metadata.version}")
    if any(keyword in cipher for keyword in WEAK_CIPHER_KEYWORDS):
        findings.append(f"weak_cipher={metadata.cipher}")
    if metadata.self_signed:
        findings.append("self_signed_certificate")
    if metadata.expired:
        findings.append("expired_certificate")
    if alpn and alpn not in EXPECTED_ALPN:
        findings.append(f"unusual_alpn={metadata.alpn}")
    if metadata.missing_sni or _client_hello_without_sni(packet, metadata):
        findings.append("missing_sni")
    return findings


def _client_hello_without_sni(packet: PacketRecord, metadata: TlsMetadata) -> bool:
    text = packet.raw_summary.lower()
    if metadata.sni:
        return False
    return ("clienthello" in text or "client hello" in text) and "sni=" in text


def _extract_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^;\s,|]+)")
    for key, value in pattern.findall(text):
        values[key] = value.strip().strip("\"'")
    return values


def _truthy(value: str | None) -> bool:
    return bool(value and value.strip().lower() in {"1", "true", "yes", "y"})
