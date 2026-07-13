from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


class PcapLoadError(RuntimeError):
    """Raised when a pcap file cannot be loaded."""


class PcapLoader:
    def load(self, path: str | Path) -> Iterable[Any]:
        pcap_path = Path(path)
        if not pcap_path.exists():
            raise PcapLoadError(f"pcap file does not exist: {pcap_path}")
        if not pcap_path.is_file():
            raise PcapLoadError(f"Not a valid file: {pcap_path}")

        try:
            from scapy.utils import PcapReader
        except ImportError as exc:
            raise PcapLoadError("Scapy is required. Install the dependencies from requirements.txt.") from exc

        try:
            reader = PcapReader(str(pcap_path))
        except Exception as exc:
            raise PcapLoadError(f"Could not open pcap file: {exc}") from exc

        try:
            for packet in reader:
                yield packet
        finally:
            reader.close()
