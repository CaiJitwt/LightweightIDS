from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import re
from typing import Any

from models import PacketRecord


class PacketFilterError(ValueError):
    pass


Node = tuple[Any, ...]

PROTOCOLS = {
    "arp",
    "dhcp",
    "dns",
    "http",
    "https",
    "icmp",
    "icmpv6",
    "ip",
    "ipv6",
    "llmnr",
    "mdns",
    "nbns",
    "ntp",
    "quic",
    "tcp",
    "tls",
    "udp",
}

FIELD_ALIASES = {
    "ip.addr": "ip.addr",
    "ip.src": "ip.src",
    "ip.dst": "ip.dst",
    "ipv6.addr": "ipv6.addr",
    "ipv6.src": "ipv6.src",
    "ipv6.dst": "ipv6.dst",
    "tcp.port": "tcp.port",
    "tcp.srcport": "tcp.srcport",
    "tcp.dstport": "tcp.dstport",
    "udp.port": "udp.port",
    "udp.srcport": "udp.srcport",
    "udp.dstport": "udp.dstport",
    "frame.len": "frame.len",
    "tcp.len": "frame.len",
    "protocol": "protocol",
    "dns.qry.name": "dns.qry.name",
    "http.host": "http.host",
    "http.request.method": "http.request.method",
    "http.request.uri": "http.request.uri",
    "tcp.flags.syn": "tcp.flags.syn",
    "tcp.flags.ack": "tcp.flags.ack",
    "tcp.flags.fin": "tcp.flags.fin",
    "tcp.flags.reset": "tcp.flags.reset",
    "tcp.flags.rst": "tcp.flags.reset",
    "summary": "summary",
}

COMPARISON_OPERATORS = {"==", "!=", ">", ">=", "<", "<=", "contains"}

_TOKEN_RE = re.compile(
    r"\s*(?:(==|!=|>=|<=|&&|\|\||[><!])|(\()|(\))|"
    r"(\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')|([^\s()=!<>]+))"
)


@dataclass(frozen=True)
class PacketFilter:
    expression: str
    capture_filter: str
    _tree: Node | None

    @classmethod
    def compile(cls, expression: str) -> PacketFilter:
        cleaned = expression.strip()
        if not cleaned:
            return cls(expression="", capture_filter="", _tree=None)

        tree = _Parser(_tokenize(cleaned)).parse()
        capture_filter, _ = _to_bpf(tree)
        return cls(expression=cleaned, capture_filter=capture_filter or "", _tree=tree)

    def matches(self, packet: PacketRecord) -> bool:
        return True if self._tree is None else _matches(self._tree, packet)


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.position = 0

    def parse(self) -> Node:
        if not self.tokens:
            raise PacketFilterError("Filter expression is empty.")
        tree = self._parse_or()
        if self._peek() is not None:
            raise PacketFilterError(f"Unexpected token: {self._peek()}")
        return tree

    def _parse_or(self) -> Node:
        node = self._parse_and()
        while self._peek_lower() in {"or", "||"}:
            self._take()
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Node:
        node = self._parse_not()
        while True:
            token = self._peek_lower()
            if token in {"and", "&&"}:
                self._take()
                node = ("and", node, self._parse_not())
            elif token is not None and token not in {"or", "||", ")"}:
                node = ("and", node, self._parse_not())
            else:
                return node

    def _parse_not(self) -> Node:
        if self._peek_lower() in {"not", "!"}:
            self._take()
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Node:
        if self._peek() == "(":
            self._take()
            node = self._parse_or()
            if self._take() != ")":
                raise PacketFilterError("Missing closing parenthesis.")
            return node
        return self._parse_term()

    def _parse_term(self) -> Node:
        token = self._take()
        if token is None:
            raise PacketFilterError("Filter expression ended unexpectedly.")
        lowered = token.lower()

        if lowered in PROTOCOLS:
            return ("protocol", lowered)

        if lowered in {"src", "dst"}:
            qualifier = self._take_lower()
            if qualifier not in {"host", "net", "port", "portrange"}:
                raise PacketFilterError(f"Expected host, net, port, or portrange after {token}.")
            return self._endpoint(lowered, qualifier)

        if lowered in {"host", "net", "port", "portrange"}:
            return self._endpoint("any", lowered)

        if lowered in {"greater", "less"}:
            value = self._integer(self._take(), "packet length")
            return ("field", "frame.len", ">" if lowered == "greater" else "<", value)

        field = FIELD_ALIASES.get(lowered)
        if field is None:
            raise PacketFilterError(f"Unsupported filter field or protocol: {token}")

        operator = self._take_lower()
        operator = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}.get(
            operator or "", operator
        )
        if operator not in COMPARISON_OPERATORS:
            raise PacketFilterError(f"Expected a comparison operator after {token}.")
        value = self._take()
        if value is None:
            raise PacketFilterError(f"Missing value after {token} {operator}.")
        if (field.startswith("ip.") or field.startswith("ipv6.") or field == "protocol" or field.startswith("tcp.flags.")) and operator not in {
            "==",
            "!=",
        }:
            raise PacketFilterError(f"{field} supports only == and != comparisons.")
        return ("field", field, operator, _prepare_field_value(field, value))

    def _endpoint(self, direction: str, qualifier: str) -> Node:
        value = self._take()
        if value is None:
            raise PacketFilterError(f"Missing value after {qualifier}.")
        if qualifier == "port":
            value = self._port(value)
        elif qualifier == "portrange":
            value = _parse_port_range(value)
        elif qualifier == "net":
            try:
                value = ip_network(value, strict=False)
            except ValueError as exc:
                raise PacketFilterError(f"Invalid network: {value}") from exc
        elif qualifier == "host":
            try:
                value = ip_address(value)
            except ValueError:
                pass
        return ("endpoint", direction, qualifier, value)

    def _port(self, value: str) -> int:
        port = self._integer(value, "port")
        if not 0 <= port <= 65535:
            raise PacketFilterError(f"Port is outside 0-65535: {port}")
        return port

    def _integer(self, value: str | None, label: str) -> int:
        try:
            return int(value or "")
        except ValueError as exc:
            raise PacketFilterError(f"Invalid {label}: {value}") from exc

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _peek_lower(self) -> str | None:
        token = self._peek()
        return token.lower() if token is not None else None

    def _take(self) -> str | None:
        token = self._peek()
        if token is not None:
            self.position += 1
        return token

    def _take_lower(self) -> str | None:
        token = self._take()
        return token.lower() if token is not None else None


def _tokenize(expression: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(expression):
        match = _TOKEN_RE.match(expression, position)
        if match is None:
            if expression[position:].strip():
                raise PacketFilterError(f"Could not parse filter near: {expression[position:]}")
            break
        token = next((group for group in match.groups() if group is not None), "")
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
            token = token[1:-1].replace(f"\\{token[0]}", token[0])
        tokens.append(token)
        position = match.end()
    return tokens


def _prepare_field_value(field: str, value: str) -> object:
    if field in {"frame.len", "tcp.port", "tcp.srcport", "tcp.dstport", "udp.port", "udp.srcport", "udp.dstport"}:
        try:
            number = int(value)
        except ValueError as exc:
            raise PacketFilterError(f"Expected a number for {field}: {value}") from exc
        if field != "frame.len" and not 0 <= number <= 65535:
            raise PacketFilterError(f"Port is outside 0-65535: {number}")
        return number
    if field.startswith("ip.") or field.startswith("ipv6."):
        try:
            return ip_network(value, strict=False) if "/" in value else ip_address(value)
        except ValueError as exc:
            raise PacketFilterError(f"Invalid IP address or network: {value}") from exc
    if field.startswith("tcp.flags."):
        lowered = value.lower()
        if lowered in {"1", "true", "set"}:
            return True
        if lowered in {"0", "false", "unset"}:
            return False
        raise PacketFilterError(f"TCP flag value must be 0/1 or true/false: {value}")
    return value


def _parse_port_range(value: str) -> tuple[int, int]:
    parts = re.split(r"[-:]", value, maxsplit=1)
    if len(parts) != 2:
        raise PacketFilterError(f"Invalid port range: {value}")
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise PacketFilterError(f"Invalid port range: {value}") from exc
    if not 0 <= start <= end <= 65535:
        raise PacketFilterError(f"Port range is outside 0-65535: {value}")
    return start, end


def _matches(node: Node, packet: PacketRecord) -> bool:
    kind = node[0]
    if kind == "and":
        return _matches(node[1], packet) and _matches(node[2], packet)
    if kind == "or":
        return _matches(node[1], packet) or _matches(node[2], packet)
    if kind == "not":
        return not _matches(node[1], packet)
    if kind == "protocol":
        return _protocol_matches(packet, node[1])
    if kind == "endpoint":
        return _endpoint_matches(packet, node[1], node[2], node[3])
    if kind == "field":
        return _field_matches(packet, node[1], node[2], node[3])
    return False


def _protocol_matches(packet: PacketRecord, expected: str) -> bool:
    actual = (packet.protocol or "UNKNOWN").lower()
    if expected == "tcp":
        return actual in {"tcp", "http", "https", "tls"} or (actual == "dns" and packet.tcp_flags is not None)
    if expected == "udp":
        return actual in {"udp", "dhcp", "mdns", "llmnr", "nbns", "ntp", "quic"} or (
            actual == "dns" and packet.tcp_flags is None
        )
    if expected == "ip":
        return any(_ip_version(value) == 4 for value in (packet.src_ip, packet.dst_ip))
    if expected == "ipv6":
        return any(_ip_version(value) == 6 for value in (packet.src_ip, packet.dst_ip))
    if expected == "icmpv6":
        return actual in {"icmpv6", "icmp6"}
    return actual == expected


def _endpoint_matches(packet: PacketRecord, direction: str, qualifier: str, expected: object) -> bool:
    if qualifier in {"host", "net"}:
        values = _directed_values(packet.src_ip, packet.dst_ip, direction)
        return any(_address_matches(value, expected) for value in values if value)

    values = _directed_values(packet.src_port, packet.dst_port, direction)
    if qualifier == "port":
        return any(value == expected for value in values if value is not None)
    start, end = expected  # type: ignore[misc]
    return any(start <= value <= end for value in values if value is not None)


def _field_matches(packet: PacketRecord, field: str, operator: str, expected: object) -> bool:
    if field == "protocol":
        matched = _protocol_matches(packet, str(expected).lower())
        return matched if operator == "==" else not matched if operator == "!=" else False

    if field.startswith("ip.") or field.startswith("ipv6."):
        direction = "src" if field.endswith(".src") else "dst" if field.endswith(".dst") else "any"
        version = 6 if field.startswith("ipv6.") else None
        values = [value for value in _directed_values(packet.src_ip, packet.dst_ip, direction) if value]
        results = [_address_matches(value, expected, version) for value in values]
        if operator == "==":
            return any(results)
        return bool(results) and all(not result for result in results)

    if field.startswith("tcp.") or field.startswith("udp."):
        if field.startswith("tcp.flags."):
            if not _protocol_matches(packet, "tcp"):
                return False
            flag = {"syn": "S", "ack": "A", "fin": "F", "reset": "R"}[field.rsplit(".", 1)[1]]
            actual = bool(packet.tcp_flags and flag in packet.tcp_flags)
            return _compare(actual, operator, expected)
        family = field.split(".", 1)[0]
        if not _protocol_matches(packet, family):
            return False
        direction = "src" if field.endswith("srcport") else "dst" if field.endswith("dstport") else "any"
        values = [value for value in _directed_values(packet.src_port, packet.dst_port, direction) if value is not None]
        return _combine_comparisons([_compare(value, operator, expected) for value in values], operator)

    field_value = {
        "frame.len": packet.length,
        "dns.qry.name": packet.dns_query,
        "http.host": packet.http_host,
        "http.request.method": packet.http_method,
        "http.request.uri": packet.http_path,
        "summary": packet.raw_summary,
    }.get(field)
    if field_value is None:
        return False
    return _compare(field_value, operator, expected)


def _directed_values(source: Any, destination: Any, direction: str) -> list[Any]:
    if direction == "src":
        return [source]
    if direction == "dst":
        return [destination]
    return [source, destination]


def _combine_comparisons(results: list[bool], operator: str) -> bool:
    if not results:
        return False
    return all(results) if operator == "!=" else any(results)


def _compare(actual: object, operator: str, expected: object) -> bool:
    if operator == "contains":
        return str(expected).lower() in str(actual).lower()
    if operator == "==":
        return str(actual).lower() == str(expected).lower()
    if operator == "!=":
        return str(actual).lower() != str(expected).lower()
    try:
        left, right = float(actual), float(expected)
    except (TypeError, ValueError):
        return False
    return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right}[operator]


def _address_matches(value: str, expected: object, version: int | None = None) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return str(value).lower() == str(expected).lower()
    if version is not None and address.version != version:
        return False
    if hasattr(expected, "network_address"):
        return address in expected  # type: ignore[operator]
    return address == expected


def _ip_version(value: str | None) -> int | None:
    try:
        return ip_address(value or "").version
    except ValueError:
        return None


def _to_bpf(node: Node) -> tuple[str | None, bool]:
    kind = node[0]
    if kind in {"and", "or"}:
        left, left_exact = _to_bpf(node[1])
        right, right_exact = _to_bpf(node[2])
        if kind == "and":
            parts = [part for part in (left, right) if part]
            return (f"({f' {kind} '.join(parts)})" if parts else None, left_exact and right_exact)
        if left is None or right is None:
            return None, left_exact and right_exact
        return f"({left} or {right})", left_exact and right_exact
    if kind == "not":
        value, exact = _to_bpf(node[1])
        return (f"not ({value})" if value and exact else None, exact)
    if kind == "protocol":
        return _protocol_bpf(node[1])
    if kind == "endpoint":
        direction, qualifier, value = node[1], node[2], node[3]
        prefix = "" if direction == "any" else f"{direction} "
        if qualifier == "portrange":
            value = f"{value[0]}-{value[1]}"
        return f"{prefix}{qualifier} {value}", True
    return _field_bpf(node[1], node[2], node[3])


def _protocol_bpf(protocol: str) -> tuple[str, bool]:
    exact = {
        "arp": "arp",
        "icmp": "icmp",
        "icmpv6": "icmp6",
        "ip": "ip",
        "ipv6": "ip6",
        "tcp": "tcp",
        "udp": "udp",
    }
    if protocol in exact:
        return exact[protocol], True
    approximate = {
        "dhcp": "(udp port 67 or udp port 68)",
        "dns": "(udp port 53 or tcp port 53)",
        "http": "(tcp port 80 or tcp port 8000 or tcp port 8080 or tcp port 8888)",
        "https": "tcp port 443",
        "llmnr": "udp port 5355",
        "mdns": "udp port 5353",
        "nbns": "udp port 137",
        "ntp": "udp port 123",
        "quic": "udp port 443",
        "tls": "tcp port 443",
    }
    return approximate[protocol], False


def _field_bpf(field: str, operator: str, expected: object) -> tuple[str | None, bool]:
    if field == "protocol" and operator in {"==", "!="}:
        value, exact = _protocol_bpf(str(expected).lower())
        return (f"not ({value})" if operator == "!=" and exact else value if operator == "==" else None, exact)

    if field.startswith("ip.") or field.startswith("ipv6."):
        if operator not in {"==", "!="}:
            return None, False
        direction = "src " if field.endswith(".src") else "dst " if field.endswith(".dst") else ""
        qualifier = "net" if hasattr(expected, "network_address") else "host"
        value = f"{direction}{qualifier} {expected}"
        return (f"not ({value})" if operator == "!=" else value, operator == "==")

    if field == "frame.len":
        return (f"len {operator} {expected}" if operator != "contains" else None, operator != "contains")

    if field.startswith("tcp.port") or field.startswith("udp.port") or field.endswith("srcport") or field.endswith("dstport"):
        family = field.split(".", 1)[0]
        direction = "src " if field.endswith("srcport") else "dst " if field.endswith("dstport") else ""
        if operator in {"==", "!="}:
            value = f"({family} and {direction}port {expected})"
            return (f"not {value}" if operator == "!=" else value, operator == "==")
        return family, False

    if field.startswith("tcp.flags.") and operator in {"==", "!="}:
        flag_name = "tcp-rst" if field.endswith(("reset", "rst")) else f"tcp-{field.rsplit('.', 1)[1]}"
        should_be_set = bool(expected) == (operator == "==")
        comparison = "!= 0" if should_be_set else "= 0"
        return f"(tcp and (tcp[tcpflags] & {flag_name} {comparison}))", True

    if field == "dns.qry.name":
        return _protocol_bpf("dns")[0], False
    if field.startswith("http."):
        return _protocol_bpf("http")[0], False
    return None, False
