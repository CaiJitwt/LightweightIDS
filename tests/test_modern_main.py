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

    assert modern_main.main(["--no-browser", "--api-port", "8787", "--frontend-port", "4173"]) == 0
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

    assert modern_main.main(["--no-browser", "--api-port", "8787"]) == 1
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


def test_available_port_can_be_bound():
    import socket

    port = modern_main._available_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", port))


def test_start_frontend_uses_selected_port_and_api_target(monkeypatch):
    captured: dict[str, object] = {}

    class Process:
        pass

    def fake_popen(command, *, cwd, env):
        captured.update(command=command, cwd=cwd, env=env)
        return Process()

    monkeypatch.setattr(modern_main.shutil, "which", lambda _name: "node")
    monkeypatch.setattr(modern_main.subprocess, "Popen", fake_popen)

    process = modern_main._start_frontend(43123, "http://127.0.0.1:49876")

    assert isinstance(process, Process)
    assert captured["command"][-3:] == ["--port", "43123", "--strictPort"]
    assert captured["cwd"] == modern_main.FRONTEND_ROOT
    assert captured["env"]["VITE_IDS_API_PROXY_TARGET"] == "http://127.0.0.1:49876"
