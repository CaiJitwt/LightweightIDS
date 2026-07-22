from __future__ import annotations

import main


def test_launcher_dispatches_named_modes(monkeypatch):
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(main, "_run_desktop", lambda args: calls.append(("desktop", args)) or 10)
    monkeypatch.setattr(main, "_run_modern", lambda args: calls.append(("modern", args)) or 20)
    monkeypatch.setattr(main, "_run_demo", lambda args: calls.append(("demo", args)) or 30)
    monkeypatch.setattr(main, "_run_cli", lambda args: calls.append(("cli", args)) or 40)

    assert main.main([]) == 10
    assert main.main(["desktop", "-style", "Fusion"]) == 10
    assert main.main(["modern", "--no-browser"]) == 20
    assert main.main(["web", "--api-port", "0"]) == 20
    assert main.main(["demo", "--port", "8000"]) == 30
    assert main.main(["cli", "status"]) == 40
    assert calls == [
        ("desktop", []),
        ("desktop", ["-style", "Fusion"]),
        ("modern", ["--no-browser"]),
        ("modern", ["--api-port", "0"]),
        ("demo", ["--port", "8000"]),
        ("cli", ["status"]),
    ]


def test_launcher_preserves_legacy_cli_and_qt_arguments(monkeypatch):
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(main, "_run_desktop", lambda args: calls.append(("desktop", args)) or 0)
    monkeypatch.setattr(main, "_run_cli", lambda args: calls.append(("cli", args)) or 0)

    assert main.main(["--cli", "status"]) == 0
    assert main.main(["-style", "Fusion"]) == 0
    assert calls == [("cli", ["status"]), ("desktop", ["-style", "Fusion"])]


def test_launcher_help_lists_integrated_entrypoints(capsys):
    assert main.main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "python main.py modern" in output
    assert "python main.py demo" in output
    assert "python main.py cli" in output
