from __future__ import annotations

import modern_main


def test_modern_launcher_reuses_running_services_and_honors_no_browser(monkeypatch, capsys):
    opened: list[str] = []

    monkeypatch.setattr(modern_main, "is_process_elevated", lambda: False)
    monkeypatch.setattr(modern_main, "_http_ready", lambda _url, _marker: True)
    monkeypatch.setattr(
        modern_main,
        "_read_json",
        lambda _url: {
            "service": "Lightweight IDS local API",
            "apiVersion": modern_main.LOCAL_API_VERSION,
            "capabilities": sorted(modern_main.REQUIRED_API_CAPABILITIES),
            "database": str(modern_main.DEFAULT_DATABASE_PATH.resolve()),
        },
    )
    monkeypatch.setattr(modern_main.webbrowser, "open", opened.append)
    monkeypatch.setattr(modern_main.time, "sleep", lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt))

    assert modern_main.main(["--no-browser"]) == 0
    assert opened == []
    output = capsys.readouterr().out
    assert "Reusing local API" in output
    assert "Reusing modern frontend" in output
    assert "Stopping Lightweight IDS modern frontend" in output


def test_modern_launcher_rejects_an_outdated_local_api(monkeypatch, capsys):
    monkeypatch.setattr(modern_main, "is_process_elevated", lambda: False)
    monkeypatch.setattr(
        modern_main,
        "_read_json",
        lambda _url: {"service": "Lightweight IDS local API", "apiVersion": 1},
    )

    assert modern_main.main(["--no-browser"]) == 1
    error = capsys.readouterr().err
    assert "incompatible local API" in error
    assert "expected API" in error


def test_modern_launcher_rejects_non_elevated_api_for_elevated_launcher():
    payload = {
        "service": "Lightweight IDS local API",
        "apiVersion": modern_main.LOCAL_API_VERSION,
        "capabilities": sorted(modern_main.REQUIRED_API_CAPABILITIES),
        "database": str(modern_main.DEFAULT_DATABASE_PATH.resolve()),
        "elevated": False,
    }

    error = modern_main._api_compatibility_error(
        payload,
        modern_main.DEFAULT_DATABASE_PATH,
        require_elevated=True,
    )

    assert error is not None
    assert "not elevated" in error
