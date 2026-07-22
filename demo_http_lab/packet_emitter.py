from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Callable

from demo_http_lab.scenarios import SCENARIO_BY_ID, SCENARIOS, DemoScenario


DEMO_SOURCE_NETWORK = "192.0.2"
DEMO_DESTINATION_IP = "192.0.2.200"
CUSTOM_SOURCE_START = 100
CUSTOM_SOURCE_COUNT = 90


class PacketEmissionError(RuntimeError):
    """Raised when a demo frame cannot be injected into the capture adapter."""


@dataclass(frozen=True)
class PacketEmissionResult:
    interface: str
    interface_description: str
    source_ip: str
    destination_ip: str
    destination_port: int

    def as_payload(self) -> dict[str, object]:
        return {
            "emitted": True,
            "interface": self.interface,
            "interfaceDescription": self.interface_description,
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "destinationPort": self.destination_port,
        }


class DefaultInterfacePacketEmitter:
    """Inject one inert HTTP frame into Scapy's default capture adapter."""

    def __init__(
        self,
        *,
        interface: str | None = None,
        destination_port: int = 8080,
        sender: Callable[..., object] | None = None,
    ) -> None:
        try:
            from scapy.all import conf, get_if_hwaddr, sendp
            from scapy.interfaces import resolve_iface
        except ImportError as exc:
            raise PacketEmissionError(
                "Scapy is required for demo packet injection. "
                "Start the demo with the same Python environment as modern_main.py."
            ) from exc

        try:
            resolved = resolve_iface(interface) if interface else conf.iface
            mac_address = str(get_if_hwaddr(resolved))
        except Exception as exc:
            requested = interface or "the default interface"
            raise PacketEmissionError(f"Could not resolve {requested}: {exc}") from exc

        if not mac_address or mac_address == "00:00:00:00:00:00":
            raise PacketEmissionError("The selected interface does not expose a usable hardware address.")

        self._interface = resolved
        self._mac_address = mac_address
        self._destination_port = destination_port
        self._sender = sender or sendp
        self._lock = Lock()
        self._custom_sequence = 0
        self.interface = str(getattr(resolved, "name", None) or resolved)
        self.interface_description = str(getattr(resolved, "description", "") or "")

    @property
    def interface_label(self) -> str:
        if self.interface_description and self.interface_description != self.interface:
            return f"{self.interface} ({self.interface_description})"
        return self.interface

    def emit(self, scenario_id: str, submitted_body: bytes = b"") -> PacketEmissionResult:
        scenario = SCENARIO_BY_ID.get(scenario_id)
        with self._lock:
            if scenario is not None:
                packet = build_demo_packet(
                    scenario,
                    destination_port=self._destination_port,
                    source_mac=self._mac_address,
                    destination_mac=self._mac_address,
                )
                source_ip = demo_source_ip(scenario)
            elif scenario_id == "custom" and submitted_body:
                sequence = self._custom_sequence
                self._custom_sequence = (self._custom_sequence + 1) % CUSTOM_SOURCE_COUNT
                packet = build_custom_demo_packet(
                    submitted_body,
                    sequence=sequence,
                    destination_port=self._destination_port,
                    source_mac=self._mac_address,
                    destination_mac=self._mac_address,
                )
                source_ip = custom_source_ip(sequence)
            else:
                raise PacketEmissionError("The custom demo payload cannot be empty.")

            try:
                self._sender(packet, iface=self._interface, verbose=False)
            except Exception as exc:
                raise PacketEmissionError(
                    f"Could not inject the demo frame on {self.interface_label}: {exc}. "
                    "Run the demo as Administrator and verify Npcap."
                ) from exc

        return PacketEmissionResult(
            interface=self.interface,
            interface_description=self.interface_description,
            source_ip=source_ip,
            destination_ip=DEMO_DESTINATION_IP,
            destination_port=self._destination_port,
        )


def build_demo_packet(
    scenario: DemoScenario,
    *,
    destination_port: int = 8080,
    source_mac: str = "02:00:00:00:00:10",
    destination_mac: str = "02:00:00:00:00:20",
) -> object:
    index = SCENARIOS.index(scenario)
    return _build_http_packet(
        scenario.id,
        scenario.body.encode("ascii"),
        source_ip=demo_source_ip(scenario),
        source_port=51_000 + index,
        ip_id=20_000 + index,
        destination_port=destination_port,
        source_mac=source_mac,
        destination_mac=destination_mac,
    )


def build_custom_demo_packet(
    body: bytes,
    *,
    sequence: int = 0,
    destination_port: int = 8080,
    source_mac: str = "02:00:00:00:00:10",
    destination_mac: str = "02:00:00:00:00:20",
) -> object:
    normalized_sequence = sequence % CUSTOM_SOURCE_COUNT
    return _build_http_packet(
        "custom",
        body,
        source_ip=custom_source_ip(normalized_sequence),
        source_port=51_100 + normalized_sequence,
        ip_id=20_100 + normalized_sequence,
        destination_port=destination_port,
        source_mac=source_mac,
        destination_mac=destination_mac,
    )


def _build_http_packet(
    scenario_id: str,
    body: bytes,
    *,
    source_ip: str,
    source_port: int,
    ip_id: int,
    destination_port: int,
    source_mac: str,
    destination_mac: str,
) -> object:
    try:
        from scapy.all import Ether, IP, Raw, TCP
    except ImportError as exc:
        raise PacketEmissionError("Scapy is required to build demo packets.") from exc

    crlf = chr(13) + chr(10)
    request = (
        f"POST /sink/{scenario_id} HTTP/1.1{crlf}"
        f"Host: ids-demo.local:{destination_port}{crlf}"
        f"Content-Type: application/x-www-form-urlencoded{crlf}"
        f"Content-Length: {len(body)}{crlf}"
        f"Connection: close{crlf}{crlf}"
    ).encode("ascii") + body
    return (
        Ether(src=source_mac, dst=destination_mac)
        / IP(src=source_ip, dst=DEMO_DESTINATION_IP, id=ip_id)
        / TCP(sport=source_port, dport=destination_port, flags="PA", seq=1_000 + ip_id)
        / Raw(load=request)
    )


def demo_source_ip(scenario: DemoScenario) -> str:
    return f"{DEMO_SOURCE_NETWORK}.{10 + SCENARIOS.index(scenario)}"


def custom_source_ip(sequence: int) -> str:
    return f"{DEMO_SOURCE_NETWORK}.{CUSTOM_SOURCE_START + sequence % CUSTOM_SOURCE_COUNT}"