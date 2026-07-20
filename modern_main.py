from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
from threading import Thread
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

from app.constants import DEFAULT_DATABASE_PATH
from endpoint_security import is_process_elevated
from modern_ui.local_api import LOCAL_API_VERSION, LocalApiServer
from storage.database import Database


PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_ROOT = PROJECT_ROOT / "modern_frontend"
REQUIRED_API_CAPABILITIES = {
    "endpoint-security-v1",
    "system-health-v1",
    "topology-v1",
    "timeline-v1",
    "resource-monitor-v1",
    "analyst-workflow-v1",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Lightweight IDS modern frontend and local API.")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE_PATH)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the frontend in the default browser.")
    parser.add_argument("--skip-install", action="store_true", help="Do not install missing frontend dependencies.")
    parser.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1). Use 0.0.0.0 to allow remote access.")
    parser.add_argument("--api-port", type=int, default=0, help="Local API port. Use 0 to select an available port automatically.")
    parser.add_argument("--frontend-port", type=int, default=0, help="Frontend port. Use 0 to select an available port automatically.")
    args = parser.parse_args(argv)
    if not 0 <= args.api_port <= 65535 or not 0 <= args.frontend_port <= 65535:
        parser.error("Ports must be between 0 and 65535.")

    api_key = ""
    if args.bind not in {"127.0.0.1", "localhost", "::1"}:
        api_key = secrets.token_hex(16)
        print(f"Remote access enabled. API key required: {api_key}")
        print("Clients must include header: X-API-Key: " + api_key)

    api_server: LocalApiServer | None = None
    api_thread: Thread | None = None
    frontend_process: subprocess.Popen[bytes] | None = None

    try:
        api_url = f"http://127.0.0.1:{args.api_port}" if args.api_port else ""
        api_health = _read_json(f"{api_url}/api/health") if api_url else None
        if api_health is not None:
            compatibility_error = _api_compatibility_error(
                api_health,
                args.database,
                require_elevated=is_process_elevated(),
            )
            if compatibility_error:
                raise RuntimeError(
                    f"Port {args.api_port} is already serving an incompatible local API: {compatibility_error} "
                    "Stop the older modern_main.py or modern_ui.local_api process, then start again."
                )
            print(f"Reusing local API at {api_url}")
        else:
            database = Database(args.database)
            database.initialize()
            api_server = LocalApiServer((args.bind, args.api_port), database, api_key=api_key)
            api_port = int(api_server.server_address[1])
            api_url = f"http://127.0.0.1:{api_port}"
            api_thread = Thread(target=api_server.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
            api_thread.start()
            print(f"Local API started at http://{args.bind}:{api_port}")

        frontend_port = args.frontend_port or _available_port()
        frontend_url = f"http://127.0.0.1:{frontend_port}"
        if args.frontend_port and _http_ready(frontend_url, b'id="root"'):
            print(f"Reusing modern frontend at {frontend_url}")
        else:
            _ensure_frontend_dependencies(install=not args.skip_install)
            frontend_process = _start_frontend(frontend_port, api_url)
            if not _wait_until_ready(frontend_url, frontend_process):
                raise RuntimeError("The modern frontend did not become ready. Review the Vite output above.")
            print(f"Modern frontend started at {frontend_url}")

        if not args.no_browser:
            webbrowser.open(frontend_url)
        print("Press Ctrl+C to stop services started by this launcher.")

        while True:
            if frontend_process is not None and frontend_process.poll() is not None:
                raise RuntimeError(f"The frontend process stopped with exit code {frontend_process.returncode}.")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping Lightweight IDS modern frontend...")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        return 1
    finally:
        _stop_process(frontend_process)
        if api_server is not None:
            api_server.shutdown()
            api_server.server_close()
        if api_thread is not None:
            api_thread.join(timeout=3)


def _ensure_frontend_dependencies(*, install: bool) -> None:
    vite_entry = FRONTEND_ROOT / "node_modules" / "vite" / "bin" / "vite.js"
    if vite_entry.exists():
        return
    if not install:
        raise RuntimeError("Frontend dependencies are missing. Run `npm install` in modern_frontend first.")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm") or shutil.which("npm")
    if npm is None:
        raise RuntimeError("Node.js and npm are required to install the modern frontend dependencies.")
    print("Frontend dependencies are missing; running npm install once...")
    completed = subprocess.run([npm, "install"], cwd=FRONTEND_ROOT, check=False)
    if completed.returncode != 0 or not vite_entry.exists():
        raise RuntimeError("npm install failed. Review the npm output above.")


def _available_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind((host, 0))
        return int(candidate.getsockname()[1])


def _start_frontend(port: int, api_url: str) -> subprocess.Popen[bytes]:
    node = shutil.which("node.exe" if os.name == "nt" else "node") or shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required to run the modern frontend.")
    vite_entry = FRONTEND_ROOT / "node_modules" / "vite" / "bin" / "vite.js"
    environment = os.environ.copy()
    environment["VITE_IDS_API_PROXY_TARGET"] = api_url
    return subprocess.Popen(
        [node, str(vite_entry), "--host", "127.0.0.1", "--port", str(port), "--strictPort"],
        cwd=FRONTEND_ROOT,
        env=environment,
    )


def _wait_until_ready(url: str, process: subprocess.Popen[bytes], timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if _http_ready(url, b'id="root"'):
            return True
        time.sleep(0.2)
    return False


def _http_ready(url: str, marker: bytes) -> bool:
    try:
        with urlopen(url, timeout=0.5) as response:
            return response.status == 200 and marker in response.read(64 * 1024)
    except (OSError, URLError):
        return False


def _read_json(url: str) -> dict[str, object] | None:
    try:
        with urlopen(url, timeout=0.8) as response:
            payload = json.loads(response.read(64 * 1024))
        return payload if response.status == 200 and isinstance(payload, dict) else None
    except (OSError, URLError, json.JSONDecodeError):
        return None


def _api_compatibility_error(
    payload: dict[str, object],
    database_path: Path,
    *,
    require_elevated: bool = False,
) -> str:
    if payload.get("service") != "Lightweight IDS local API":
        return "the service identity does not match"
    if payload.get("apiVersion") != LOCAL_API_VERSION:
        return f"expected API v{LOCAL_API_VERSION}, received {payload.get('apiVersion', 'unknown')}"
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list) or not REQUIRED_API_CAPABILITIES.issubset(
        {str(item) for item in capabilities}
    ):
        return "required endpoint-security capabilities are missing"
    configured_database = payload.get("database")
    try:
        running_database = Path(str(configured_database)).resolve()
    except (OSError, TypeError, ValueError):
        return "the API did not report a valid database path"
    if running_database != database_path.resolve():
        return f"it uses {running_database}, not {database_path.resolve()}"
    if require_elevated and payload.get("elevated") is not True:
        return "the existing API process is not elevated, although this launcher is elevated"
    return ""


def _stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
