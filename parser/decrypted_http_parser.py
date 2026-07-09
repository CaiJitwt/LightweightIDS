from __future__ import annotations

from datetime import datetime

from models import DecryptedHttpRecord, PacketRecord


class DecryptedHttpParser:
    def parse(self, record: DecryptedHttpRecord) -> PacketRecord:
        headers_preview = self._headers_preview(record.headers)
        body_preview = " ".join(record.body_preview.split())
        raw_parts = [
            "Decrypted HTTP log",
            f"{record.method or 'GET'} {record.path or '/'}",
            f"host={record.host}",
        ]
        if headers_preview:
            raw_parts.append(f"headers={headers_preview}")
        if body_preview:
            raw_parts.append(f"body={body_preview[:500]}")
        if record.source:
            raw_parts.append(f"source={record.source}")

        return PacketRecord(
            timestamp=record.timestamp or self._now(),
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
            protocol="HTTP",
            length=len(headers_preview) + len(body_preview),
            http_method=record.method or None,
            http_host=record.host or None,
            http_path=record.path or None,
            raw_summary=" | ".join(raw_parts),
        )

    def _headers_preview(self, headers: dict[str, str]) -> str:
        return "; ".join(f"{key}: {value}" for key, value in sorted(headers.items()))

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
