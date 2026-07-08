from __future__ import annotations

from detection.rule_base import RuleBase
from detection.rules.payload_utils import matched_keywords, packet_text
from models import AlertRecord, PacketRecord


class TlsFingerprintRule(RuleBase):
    rule_id = "TLS_FINGERPRINT"
    name = "TLS fingerprint risk"
    category = "tls"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    TLS_PROTOCOLS = {"TLS", "HTTPS", "QUIC"}
    TLS_PORTS = {443, 8443, 9443}
    WEAK_VERSION_KEYWORDS = ["sslv2", "sslv3", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1"]
    WEAK_CIPHER_KEYWORDS = ["rc4", "3des", " des ", "export", "null cipher", "md5"]
    CERT_KEYWORDS = ["self-signed", "expired certificate", "untrusted certificate"]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not self._is_tls_candidate(packet):
            return []

        text = f" {packet_text(packet)} "
        findings = (
            matched_keywords(text, self.WEAK_VERSION_KEYWORDS)
            + matched_keywords(text, self.WEAK_CIPHER_KEYWORDS)
            + matched_keywords(text, self.CERT_KEYWORDS)
        )
        if not findings:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="TLS_WEAK_FINGERPRINT",
                description="TLS handshake metadata contains weak version, weak cipher or suspicious certificate indicators.",
                evidence=(
                    f"src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; dst_port={packet.dst_port}; "
                    f"matches={sorted(set(findings))}"
                ),
            )
        ]

    def _is_tls_candidate(self, packet: PacketRecord) -> bool:
        return bool(
            packet.protocol in self.TLS_PROTOCOLS
            or packet.src_port in self.TLS_PORTS
            or packet.dst_port in self.TLS_PORTS
            or "tls" in packet_text(packet)
            or "ssl" in packet_text(packet)
        )
