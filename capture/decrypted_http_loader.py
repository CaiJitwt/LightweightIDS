from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable, Any

from models import DecryptedHttpRecord


class DecryptedHttpLoadError(RuntimeError):
    """Raised when a decrypted HTTP log cannot be loaded."""


class DecryptedHttpLoader:
    SUPPORTED_SUFFIXES = {".jsonl", ".csv"}

    def load(self, path: str | Path) -> Iterable[DecryptedHttpRecord]:
        log_path = Path(path)
        if not log_path.exists():
            raise DecryptedHttpLoadError(f"Decrypted HTTP log not found: {log_path}")
        if not log_path.is_file():
            raise DecryptedHttpLoadError(f"Not a valid decrypted HTTP log file: {log_path}")

        suffix = log_path.suffix.lower()
        if suffix == ".jsonl":
            yield from self._load_jsonl(log_path)
            return
        if suffix == ".csv":
            yield from self._load_csv(log_path)
            return
        raise DecryptedHttpLoadError("Supported decrypted HTTP log formats are JSONL and CSV.")

    def _load_jsonl(self, path: Path) -> Iterable[DecryptedHttpRecord]:
        with path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DecryptedHttpLoadError(f"Invalid JSONL at line {line_number}: {exc}") from exc
                if not isinstance(item, dict):
                    raise DecryptedHttpLoadError(f"JSONL line {line_number} must contain an object.")
                yield self._record_from_mapping(item)

    def _load_csv(self, path: Path) -> Iterable[DecryptedHttpRecord]:
        with path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                yield self._record_from_mapping(dict(row))

    def _record_from_mapping(self, data: dict[str, Any]) -> DecryptedHttpRecord:
        return DecryptedHttpRecord(
            timestamp=self._string(data.get("timestamp")),
            src_ip=self._optional_string(data.get("src_ip")),
            dst_ip=self._optional_string(data.get("dst_ip")),
            src_port=self._optional_int(data.get("src_port")),
            dst_port=self._optional_int(data.get("dst_port")),
            method=self._string(data.get("method")).upper(),
            host=self._string(data.get("host")),
            path=self._string(data.get("path")),
            headers=self._headers(data.get("headers")),
            body_preview=self._string(data.get("body_preview")),
            source=self._string(data.get("source")),
        )

    def _headers(self, value: object) -> dict[str, str]:
        if value is None or value == "":
            return {}
        if isinstance(value, dict):
            return {str(key): str(item) for key, item in value.items()}
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return self._parse_header_lines(value)
            if isinstance(parsed, dict):
                return {str(key): str(item) for key, item in parsed.items()}
        raise DecryptedHttpLoadError("headers must be a JSON object or header-line string.")

    def _parse_header_lines(self, value: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        for raw_line in value.replace("\\n", "\n").splitlines():
            if ":" not in raw_line:
                continue
            key, item = raw_line.split(":", 1)
            key = key.strip()
            if key:
                headers[key] = item.strip()
        return headers

    def _string(self, value: object) -> str:
        if value is None:
            return ""
        return str(value)

    def _optional_string(self, value: object) -> str | None:
        text = self._string(value).strip()
        return text or None

    def _optional_int(self, value: object) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            raise DecryptedHttpLoadError(f"Invalid integer value: {value}") from None
