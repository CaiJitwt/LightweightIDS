from __future__ import annotations

from threading import Event
from typing import Callable


class LiveCapture:
    def __init__(
        self,
        interface: str | None = None,
        packet_callback: Callable[[object], None] | None = None,
        idle_callback: Callable[[], None] | None = None,
        capture_filter: str | None = None,
    ) -> None:
        self.interface = interface
        self.packet_callback = packet_callback
        self.idle_callback = idle_callback
        self.capture_filter = capture_filter
        self._stop_event = Event()

    def start(self) -> None:
        try:
            from scapy.sendrecv import sniff
        except ImportError as exc:
            raise RuntimeError("缺少 Scapy，无法启动实时抓包。") from exc

        self._stop_event.clear()
        while not self._stop_event.is_set():
            sniff(
                iface=self.interface or None,
                filter=self.capture_filter or None,
                prn=self.packet_callback,
                store=False,
                timeout=1,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
            if self.idle_callback:
                self.idle_callback()

    def stop(self) -> None:
        self._stop_event.set()
