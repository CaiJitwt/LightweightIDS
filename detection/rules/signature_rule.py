from __future__ import annotations

from detection.rule_base import RuleBase
from detection.rules.payload_utils import has_inspectable_payload
from detection.signature_matcher import SignatureMatcher
from models import AlertRecord, PacketRecord


class SignatureRule(RuleBase):
    rule_id = "SIGNATURE_MATCH"
    name = "External signature match"
    category = "signature"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    def __init__(
        self,
        matcher: SignatureMatcher | None = None,
        *,
        enabled: bool | None = None,
        threshold: int | None = None,
        time_window: int | None = None,
        severity: str | None = None,
    ) -> None:
        self._severity_override = severity.upper() if severity else None
        super().__init__(enabled=enabled, threshold=threshold, time_window=time_window, severity=severity)
        self.matcher = matcher or SignatureMatcher.from_yaml()

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        if not has_inspectable_payload(packet):
            return []
        alerts: list[AlertRecord] = []
        for match in self.matcher.match_packet(packet):
            signature = match.signature
            severity = self._severity_override or signature.severity
            alerts.append(
                self.create_alert(
                    packet,
                    alert_type=signature.category.upper(),
                    description=signature.description or f"Detected signature match: {signature.name}.",
                    evidence=(
                        f"signature_id={signature.id}; signature_name={signature.name}; "
                        f"field={match.field}; matched={match.matched_text}; "
                        f"host={packet.http_host or ''}; path={packet.http_path or ''}"
                    ),
                    severity=severity,
                )
            )
        return alerts
