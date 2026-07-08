from __future__ import annotations


class InterfaceManager:
    def list_interfaces(self) -> list[str]:
        try:
            from scapy.arch import get_if_list
        except ImportError as exc:
            raise RuntimeError("缺少 Scapy，无法获取网卡列表。") from exc

        try:
            return list(get_if_list())
        except Exception as exc:
            raise RuntimeError(f"获取网卡列表失败：{exc}") from exc
