from __future__ import annotations

import ipaddress


def is_valid_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_ip(value: str | None) -> bool:
    address = parse_ip(value)
    return bool(address and address.is_private)


def is_public_ip(value: str | None) -> bool:
    address = parse_ip(value)
    if address is None:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
