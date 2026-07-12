from __future__ import annotations

from pathlib import Path

from app.constants import PROJECT_ROOT
from detection.rule_base import RuleBase
from models import AlertRecord, BlocklistEntry, PacketRecord


class BlacklistRule(RuleBase):
    rule_id = "BLACKLIST_IP"
    name = "Blacklisted IP match"
    category = "reputation"
    severity = "HIGH"
    threshold = 1
    time_window = 0

    def __init__(
        self,
        blacklist_path: str | Path | None = None,
        blacklist: set[str] | None = None,
        entries: list[BlocklistEntry] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.blacklist_path = Path(blacklist_path) if blacklist_path else PROJECT_ROOT / "config" / "blacklist.txt"
        self.blacklist = blacklist if blacklist is not None else self._load_blacklist(self.blacklist_path)
        self.entries = entries or []

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        matched_ips = [ip for ip in (packet.src_ip, packet.dst_ip) if ip and ip in self.blacklist]
        matched_entries = [entry for entry in self.entries if entry.matches(packet)]
        if not matched_ips and not matched_entries:
            return []

        evidence = (
            f"matched_ips={matched_ips}; src_ip={packet.src_ip}; dst_ip={packet.dst_ip}; "
            f"matched_entries={[f'{entry.field}={entry.value}' for entry in matched_entries]}; "
            f"blacklist_path={self.blacklist_path}"
        )
        matched_values = matched_ips + [f"{entry.field}={entry.value}" for entry in matched_entries]
        return [
            self.create_alert(
                packet,
                alert_type="BLACKLIST_IP",
                description=f"Packet matched blocked network values: {', '.join(matched_values)}.",
                evidence=evidence,
            )
        ]

    def reload(self) -> None:
        self.blacklist = self._load_blacklist(self.blacklist_path)

    def _load_blacklist(self, path: Path) -> set[str]:
        if not path.exists():
            return set()

        values: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                values.add(value)
        return values
