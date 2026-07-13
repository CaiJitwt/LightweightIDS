from __future__ import annotations


class InterfaceManager:
    def list_interfaces(self) -> list[str]:
        try:
            from scapy.arch import get_if_list
        except ImportError as exc:
            raise RuntimeError("Scapy is required to list capture interfaces.") from exc

        try:
            return list(get_if_list())
        except Exception as exc:
            raise RuntimeError(f"Could not list capture interfaces: {exc}") from exc
