from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


class PcapLoadError(RuntimeError):
    """Raised when a pcap file cannot be loaded."""


class PcapLoader:
    def load(self, path: str | Path) -> Iterable[Any]:
        pcap_path = Path(path)
        if not pcap_path.exists():
            raise PcapLoadError(f"pcap 文件不存在：{pcap_path}")
        if not pcap_path.is_file():
            raise PcapLoadError(f"不是有效文件：{pcap_path}")

        try:
            from scapy.utils import PcapReader
        except ImportError as exc:
            raise PcapLoadError("缺少 Scapy。请先安装 requirements.txt 中的依赖。") from exc

        try:
            reader = PcapReader(str(pcap_path))
        except Exception as exc:
            raise PcapLoadError(f"无法打开 pcap 文件：{exc}") from exc

        try:
            for packet in reader:
                yield packet
        finally:
            reader.close()
