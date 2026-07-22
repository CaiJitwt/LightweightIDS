from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote_plus

from models import PacketRecord


MAX_SOURCE_LENGTH = 16_384
MAX_VARIANTS = 12
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,4096}={0,2})(?![A-Za-z0-9+/])")
HEX_ESCAPE_TOKEN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
PERCENT_UNICODE = re.compile(r"%u([0-9a-fA-F]{4})")
SQL_INLINE_COMMENT = re.compile(r"/\*.{0,512}?\*/", re.DOTALL)
HTTP_RESPONSE = re.compile(r"(?i)(?:^|\|\s*payload=)\s*HTTP/\d(?:\.\d)?\s+\d{3}\b")
OPAQUE_ENCRYPTED_PROTOCOLS = {"HTTPS", "TLS", "QUIC"}


def packet_text(packet: PacketRecord) -> str:
    values = [
        packet.dns_query,
        packet.http_method,
        packet.http_host,
        packet.http_path,
    ]
    if has_inspectable_payload(packet):
        values = [raw_http_body_text(packet), packet.raw_summary, *values]
    source = " ".join(value for value in values if value)[:MAX_SOURCE_LENGTH]
    return "\n".join(canonical_text_variants(source))


def has_inspectable_payload(packet: PacketRecord) -> bool:
    """Return whether content signatures may safely inspect the packet text."""
    if is_http_response(packet):
        return False
    if packet.http_method or packet.http_host or packet.http_path:
        return True
    protocol = (packet.protocol or "").upper()
    if protocol in OPAQUE_ENCRYPTED_PROTOCOLS:
        return False
    return bool(packet.raw_summary)


def is_http_response(packet: PacketRecord) -> bool:
    """Return whether the packet carries server response content, not request input."""
    if HTTP_RESPONSE.search(packet.raw_summary or ""):
        return True
    raw_bytes = _raw_packet_bytes(packet)
    return bool(re.search(rb"HTTP/\d(?:\.\d)?\s+\d{3}\b", raw_bytes, re.IGNORECASE))


def raw_http_body_text(packet: PacketRecord) -> str:
    """Return a bounded HTTP body decoded from the retained raw packet bytes."""
    raw_bytes = _raw_packet_bytes(packet)
    if not raw_bytes:
        return ""

    markers = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")
    starts = [index for marker in markers if (index := raw_bytes.find(marker)) >= 0]
    request_bytes = raw_bytes[min(starts) :] if starts else raw_bytes
    header_end = request_bytes.find(bytes((13, 10, 13, 10)))
    if header_end >= 0:
        request_bytes = request_bytes[header_end + 4 :]
    return request_bytes.decode("utf-8", errors="replace")


def _raw_packet_bytes(packet: PacketRecord) -> bytes:
    raw_hex = packet.raw_hex or ""
    if not raw_hex:
        return b""
    try:
        return bytes.fromhex(raw_hex[: MAX_SOURCE_LENGTH * 2])
    except ValueError:
        return b""


def canonical_text_variants(source: str) -> list[str]:
    """Return bounded canonical forms for defensive signature matching."""
    variants: list[str] = []

    def add(value: str) -> None:
        normalized = unicodedata.normalize("NFKC", value)[:MAX_SOURCE_LENGTH].lower()
        if normalized and normalized not in variants and len(variants) < MAX_VARIANTS:
            variants.append(normalized)

    add(source)
    current = source
    for _ in range(2):
        decoded = unquote_plus(PERCENT_UNICODE.sub(lambda match: chr(int(match.group(1), 16)), current))
        decoded = html.unescape(decoded)
        add(decoded)
        current = decoded

    add(SQL_INLINE_COMMENT.sub("", current))
    for match in HEX_ESCAPE_TOKEN.finditer(current):
        try:
            add(bytes.fromhex(match.group(0).replace("\\x", "")).decode("utf-8", errors="replace"))
        except ValueError:
            continue

    for match in list(BASE64_TOKEN.finditer(current))[:3]:
        token = match.group(1)
        try:
            decoded_bytes = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not decoded_bytes or len(decoded_bytes) > MAX_SOURCE_LENGTH:
            continue
        printable_ratio = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in decoded_bytes) / len(decoded_bytes)
        if printable_ratio >= 0.85:
            add(decoded_bytes.decode("utf-8", errors="replace"))
    return variants


def matched_keywords(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword.lower() in lowered]
