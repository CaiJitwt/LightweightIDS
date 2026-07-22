from __future__ import annotations

import argparse
import ipaddress
import secrets
import socket
import webbrowser

from demo_http_lab.packet_emitter import DefaultInterfacePacketEmitter, PacketEmissionError
from demo_http_lab.server import DemoHttpServer


HTTP_DEMO_PORTS = (8080, 8000, 8888)
LOOPBACK_HOST = "127.0.0.1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a local HTTP sink for demonstrating Lightweight IDS alerts."
    )
    parser.add_argument(
        "--host",
        default=LOOPBACK_HOST,
        help="Bind address (default: 127.0.0.1 loopback only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        choices=HTTP_DEMO_PORTS,
        default=8080,
        help="HTTP port recognized by PacketParser (default: 8080).",
    )
    parser.add_argument(
        "--require-token",
        action="store_true",
        help="Require a generated URL token instead of using the default classroom mode.",
    )
    parser.add_argument(
        "--token",
        default="",
        help="Require this fixed token. Supplying a value also enables token protection.",
    )
    parser.add_argument(
        "--allow-network",
        action="append",
        default=[],
        metavar="CIDR",
        help="Restrict clients to an explicit network, for example 192.168.56.0/24. May be repeated.",
    )
    parser.add_argument("--advertise-host", default="", help="Address printed for advanced LAN demonstrations.")
    parser.add_argument(
        "--interface",
        default="",
        help="Capture interface used for demo frame injection (default: Scapy's default interface).",
    )
    parser.add_argument(
        "--receiver-only",
        action="store_true",
        help="Disable adapter injection and only receive/discard browser requests.",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the first advertised demo URL in the default browser after startup.",
    )
    args = parser.parse_args(argv)

    token = args.token or (secrets.token_urlsafe(18) if args.require_token else "")
    emitter = None
    if not args.receiver_only:
        try:
            emitter = DefaultInterfacePacketEmitter(
                interface=args.interface or None,
                destination_port=args.port,
            )
        except PacketEmissionError as exc:
            parser.error(str(exc))
    try:
        server = DemoHttpServer(
            (args.host, args.port),
            token=token,
            allowed_networks=args.allow_network,
            packet_emitter=None if emitter is None else emitter.emit,
        )
    except ValueError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(f"Could not bind {args.host}:{args.port}: {exc}")

    addresses = advertised_addresses(args.host, args.advertise_host)
    if not addresses:
        addresses = ["<HOST_PRIVATE_IP>"]

    print("Lightweight IDS HTTP demo lab is ready.")
    print(f"Listening on {args.host}:{args.port}; accepted bodies are discarded and never executed.")
    if token:
        print(f"Protected mode token: {token}")
    elif args.host == LOOPBACK_HOST:
        print("Local classroom mode: only this computer can connect; no token is required.")
    else:
        print("Classroom mode: private-network clients can send samples without a token.")
    print("Open this address in a browser:")
    browser_url = ""
    for address in addresses:
        suffix = f"#{token}" if token else ""
        url = f"http://{address}:{args.port}/{suffix}"
        browser_url = browser_url or url
        print(f"  {url}")
    if emitter is not None:
        print(f"Demo samples will be injected on: {emitter.interface_label}")
        if args.interface:
            print("Select this same interface in Traffic Monitor before sending scenarios.")
        else:
            print("Leave Default interface selected in Traffic Monitor before sending scenarios.")
    else:
        print("Receiver-only mode is active; browser requests will not be injected into a capture adapter.")
    print(f"Recommended capture filter: tcp.dstport == {args.port}")
    print("Press Ctrl+C to stop the demo lab.")

    if args.open_browser and browser_url:
        try:
            opened = webbrowser.open(browser_url, new=2)
        except webbrowser.Error as exc:
            print(f"Could not open the browser automatically: {exc}")
        else:
            if not opened:
                print("The browser did not open automatically; use the address printed above.")

    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping HTTP demo lab...")
    finally:
        server.server_close()
    return 0


def advertised_addresses(bind_host: str, override: str = "") -> list[str]:
    if override:
        return [override]
    if bind_host in {LOOPBACK_HOST, "localhost"}:
        return [LOOPBACK_HOST]
    if bind_host == "0.0.0.0":
        return private_ipv4_addresses()
    return [bind_host]


def private_ipv4_addresses() -> list[str]:
    candidates: set[str] = set()
    try:
        from scapy.all import get_if_addr, get_if_list

        for interface in get_if_list():
            candidates.add(str(get_if_addr(interface)))
    except (ImportError, OSError, RuntimeError):
        pass

    try:
        records = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        records = []
    for record in records:
        candidates.add(record[4][0])

    addresses: set[str] = set()
    benchmark_network = ipaddress.ip_network("198.18.0.0/15")
    for address in candidates:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            isinstance(parsed, ipaddress.IPv4Address)
            and parsed.is_private
            and not parsed.is_loopback
            and not parsed.is_link_local
            and not parsed.is_unspecified
            and parsed not in benchmark_network
        ):
            addresses.add(address)
    return sorted(addresses)


if __name__ == "__main__":
    raise SystemExit(main())
