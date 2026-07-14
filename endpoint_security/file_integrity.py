from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


class FileIntegrityService:
    """Local SHA-256 baselines for analyst-selected paths.

    This service stores names and hashes only. It never sends file contents to
    a remote service and bounds scans to keep analyst workstations responsive.
    """

    VERSION = 1

    def __init__(self, storage_dir: str | Path, max_files: int = 3_000, max_file_bytes: int = 64 * 1024 * 1024) -> None:
        self.storage_dir = Path(storage_dir)
        self.baseline_path = self.storage_dir / "integrity_baseline.json"
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

    def status(self) -> dict[str, Any]:
        baseline = self._load_baseline(required=False)
        if baseline is None:
            return {"available": False, "paths": [], "fileCount": 0, "createdAt": ""}
        return {
            "available": True,
            "paths": baseline["paths"],
            "fileCount": len(baseline["files"]),
            "createdAt": baseline["createdAt"],
        }

    def create_baseline(self, paths: list[str]) -> dict[str, Any]:
        resolved_paths = self._normalize_paths(paths)
        snapshot, skipped = self._snapshot(resolved_paths)
        baseline = {
            "version": self.VERSION,
            "createdAt": _utc_now(),
            "paths": [str(path) for path in resolved_paths],
            "files": snapshot,
            "skipped": skipped,
        }
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(baseline, ensure_ascii=True, indent=2), encoding="utf-8")
        return {"paths": baseline["paths"], "fileCount": len(snapshot), "skipped": skipped, "createdAt": baseline["createdAt"]}

    def scan(self) -> dict[str, Any]:
        baseline = self._load_baseline(required=True)
        paths = [Path(path) for path in baseline["paths"]]
        current, skipped = self._snapshot(paths)
        previous: dict[str, dict[str, Any]] = baseline["files"]
        added = sorted(path for path in current if path not in previous)
        removed = sorted(path for path in previous if path not in current)
        modified = sorted(path for path in current if path in previous and current[path]["sha256"] != previous[path]["sha256"])
        return {
            "scannedAt": _utc_now(),
            "paths": baseline["paths"],
            "fileCount": len(current),
            "added": added,
            "removed": removed,
            "modified": modified,
            "skipped": skipped,
        }

    def _load_baseline(self, required: bool) -> dict[str, Any] | None:
        if not self.baseline_path.exists():
            if required:
                raise ValueError("Create a file-integrity baseline before running a scan.")
            return None
        try:
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("The file-integrity baseline cannot be read.") from exc
        if not isinstance(baseline, dict) or baseline.get("version") != self.VERSION or not isinstance(baseline.get("files"), dict):
            raise ValueError("The file-integrity baseline has an unsupported format.")
        return baseline

    def _normalize_paths(self, paths: list[str]) -> list[Path]:
        if not paths:
            raise ValueError("Select at least one existing directory or file.")
        if len(paths) > 8:
            raise ValueError("A baseline can contain at most eight paths.")
        normalized: list[Path] = []
        for raw_path in paths:
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ValueError("Integrity paths must be non-empty strings.")
            path = Path(raw_path).expanduser().resolve()
            if not path.exists():
                raise ValueError(f"Integrity path does not exist: {path}")
            if path not in normalized:
                normalized.append(path)
        return normalized

    def _snapshot(self, paths: list[Path]) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
        records: dict[str, dict[str, Any]] = {}
        skipped: list[dict[str, str]] = []
        for root in paths:
            candidates = [root] if root.is_file() else root.rglob("*")
            for candidate in candidates:
                if len(records) >= self.max_files:
                    skipped.append({"path": str(root), "reason": f"File limit of {self.max_files} reached."})
                    return records, skipped
                if not candidate.is_file() or any(part in {".git", "node_modules", "__pycache__"} for part in candidate.parts):
                    continue
                try:
                    stat = candidate.stat()
                except OSError as exc:
                    skipped.append({"path": str(candidate), "reason": str(exc)})
                    continue
                if stat.st_size > self.max_file_bytes:
                    skipped.append({"path": str(candidate), "reason": f"Exceeds {self.max_file_bytes} byte scan limit."})
                    continue
                try:
                    records[str(candidate)] = {
                        "sha256": _hash_file(candidate),
                        "size": stat.st_size,
                        "modifiedNs": stat.st_mtime_ns,
                    }
                except OSError as exc:
                    skipped.append({"path": str(candidate), "reason": str(exc)})
        return records, skipped


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
