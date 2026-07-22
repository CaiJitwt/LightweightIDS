from __future__ import annotations

import argparse
import ipaddress
import secrets
import socket

from demo_http_lab.server import DemoHttpServer


HTTP_DEMO_PORTS = (8080, 8000, 8888)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a private-network HTTP sink for demonstrating Lightweight IDS alerts."
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: all local IPv4 interfaces).")
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
    parser.add_argument("--advertise-host", default="", help="Private host IP printed for VM users.")
    args = parser.parse_args(argv)

    token = args.token or (secrets.token_urlsafe(18) if args.require_token else "")
    try:
        server = DemoHttpServer(
            (args.host, args.port),
            token=token,
            allowed_networks=args.allow_network,
        )
    except ValueError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(f"Could not bind {args.host}:{args.port}: {exc}")

    addresses = [args.advertise_host] if args.advertise_host else private_ipv4_addresses()
    if not addresses:
        addresses = ["<HOST_PRIVATE_IP>"]

    print("Lightweight IDS HTTP demo lab is ready.")
    print(f"Listening on {args.host}:{args.port}; accepted bodies are discarded and never executed.")
    if token:
        print(f"Protected mode token: {token}")
    else:
        print("Classroom mode: private-network clients can send samples without a token.")
    print("Open an address on the same private subnet as the VM:")
    for address in addresses:
        suffix = f"#{token}" if token else ""
        print(f"  http://{address}:{args.port}/{suffix}")
    print("Start live capture on the VM-facing adapter before sending scenarios.")
    print(f"Recommended capture filter: tcp.dstport == {args.port}")
    print("Press Ctrl+C to stop the demo lab.")

    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping HTTP demo lab...")
    finally:
        server.server_close()
    return 0


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
