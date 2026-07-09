from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable

from models import PacketRecord


PACKET_FIELD_NAMES = ("raw_summary", "dns_query", "http_method", "http_host", "http_path")
DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "config" / "signatures.yaml"


@dataclass(frozen=True, slots=True)
class Signature:
    id: str
    name: str
    category: str
    severity: str
    match_type: str
    pattern: str
    description: str = ""
    fields: tuple[str, ...] = PACKET_FIELD_NAMES

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Signature id is required.")
        if not self.name:
            raise ValueError(f"Signature {self.id} must have a name.")
        if self.match_type not in {"keyword", "regex"}:
            raise ValueError(f"Signature {self.id} has unsupported match_type: {self.match_type}")
        if not self.pattern:
            raise ValueError(f"Signature {self.id} must have a pattern.")
        unknown_fields = set(self.fields) - set(PACKET_FIELD_NAMES)
        if unknown_fields:
            raise ValueError(f"Signature {self.id} has unsupported fields: {sorted(unknown_fields)}")

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Signature":
        fields = data.get("fields", PACKET_FIELD_NAMES)
        if isinstance(fields, str):
            fields = (fields,)
        return cls(
            id=str(data.get("id", "")).strip(),
            name=str(data.get("name", "")).strip(),
            category=str(data.get("category", "")).strip(),
            severity=str(data.get("severity", "LOW")).strip().upper(),
            match_type=str(data.get("match_type", data.get("type", ""))).strip().lower(),
            pattern=str(data.get("pattern", "")),
            description=str(data.get("description", "")).strip(),
            fields=tuple(str(field).strip() for field in fields),
        )


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    signature: Signature
    field: str
    value: str
    matched_text: str


class SignatureMatcher:
    def __init__(self, signatures: Iterable[Signature]) -> None:
        self.signatures = list(signatures)
        self._regex_cache: dict[str, re.Pattern[str]] = {}
        for signature in self.signatures:
            if signature.match_type == "regex":
                self._regex_cache[signature.id] = re.compile(signature.pattern, re.IGNORECASE)

    @classmethod
    def from_yaml(cls, path: str | Path = DEFAULT_SIGNATURES_PATH) -> "SignatureMatcher":
        signature_path = Path(path)
        if not signature_path.exists():
            raise FileNotFoundError(f"Signature file not found: {signature_path}")

        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load signature files.") from exc

        with signature_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        items = data.get("signatures", [])
        if not isinstance(items, list):
            raise ValueError("Signature file must contain a signatures list.")

        signatures = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Each signature entry must be a mapping.")
            signatures.append(Signature.from_mapping(item))
        return cls(signatures)

    def match_packet(self, packet: PacketRecord) -> list[SignatureMatch]:
        matches: list[SignatureMatch] = []
        for signature in self.signatures:
            match = self._match_signature(packet, signature)
            if match is not None:
                matches.append(match)
        return matches

    def _match_signature(self, packet: PacketRecord, signature: Signature) -> SignatureMatch | None:
        for field in signature.fields:
            value = getattr(packet, field)
            if not value:
                continue
            matched_text = self._match_value(str(value), signature)
            if matched_text is not None:
                return SignatureMatch(signature=signature, field=field, value=str(value), matched_text=matched_text)
        return None

    def _match_value(self, value: str, signature: Signature) -> str | None:
        if signature.match_type == "keyword":
            if signature.pattern.lower() in value.lower():
                return signature.pattern
            return None

        regex = self._regex_cache[signature.id]
        match = regex.search(value)
        if match is None:
            return None
        return match.group(0)
