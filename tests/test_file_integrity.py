from __future__ import annotations

from endpoint_security.file_integrity import FileIntegrityService


def test_file_integrity_baseline_detects_added_modified_and_removed_files(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    original = monitored / "original.txt"
    original.write_text("before", encoding="utf-8")
    removed = monitored / "removed.txt"
    removed.write_text("remove me", encoding="utf-8")

    service = FileIntegrityService(tmp_path / "state")
    baseline = service.create_baseline([str(monitored)])
    assert baseline["fileCount"] == 2

    original.write_text("after", encoding="utf-8")
    removed.unlink()
    added = monitored / "added.txt"
    added.write_text("new", encoding="utf-8")

    result = service.scan()
    assert str(original) in result["modified"]
    assert str(removed) in result["removed"]
    assert str(added) in result["added"]


def test_file_integrity_requires_an_existing_selected_path(tmp_path):
    service = FileIntegrityService(tmp_path / "state")
    try:
        service.create_baseline([str(tmp_path / "missing")])
    except ValueError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("A missing integrity path must be rejected")
