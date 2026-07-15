from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Thread
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

from app.constants import DEFAULT_DATABASE_PATH
from modern_ui.local_api import LOCAL_API_VERSION, LocalApiServer
from storage.database import Database


PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_ROOT = PROJECT_ROOT / "modern_frontend"
API_URL = "http://127.0.0.1:8787"
FRONTEND_URL = "http://127.0.0.1:4173"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Lightweight IDS modern frontend and local API.")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE_PATH)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the frontend in the default browser.")
    parser.add_argument("--skip-install", action="store_true", help="Do not install missing frontend dependencies.")
    args = parser.parse_args(argv)

    api_server: LocalApiServer | None = None
    api_thread: Thread | None = None
    frontend_process: subprocess.Popen[bytes] | None = None

    try:
        api_health = _read_json(f"{API_URL}/api/health")
        if api_health is not None:
            compatibility_error = _api_compatibility_error(api_health, args.database)
            if compatibility_error:
                raise RuntimeError(
                    f"Port 8787 is already serving an incompatible local API: {compatibility_error} "
                    "Stop the older modern_main.py or modern_ui.local_api process, then start again."
                )
            print(f"Reusing local API at {API_URL}")
        else:
            database = Database(args.database)
            database.initialize()
            api_server = LocalApiServer(("127.0.0.1", 8787), database)
            api_thread = Thread(target=api_server.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
            api_thread.start()
            print(f"Local API started at {API_URL}")

        if _http_ready(FRONTEND_URL, b'id="root"'):
            print(f"Reusing modern frontend at {FRONTEND_URL}")
        else:
            _ensure_frontend_dependencies(install=not args.skip_install)
            frontend_process = _start_frontend()
            if not _wait_until_ready(FRONTEND_URL, frontend_process):
                raise RuntimeError("The modern frontend did not become ready. Review the Vite output above.")
            print(f"Modern frontend started at {FRONTEND_URL}")

        if not args.no_browser:
            webbrowser.open(FRONTEND_URL)
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


def _start_frontend() -> subprocess.Popen[bytes]:
    node = shutil.which("node.exe" if os.name == "nt" else "node") or shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required to run the modern frontend.")
    vite_entry = FRONTEND_ROOT / "node_modules" / "vite" / "bin" / "vite.js"
    return subprocess.Popen(
        [node, str(vite_entry), "--host", "127.0.0.1", "--port", "4173", "--strictPort"],
        cwd=FRONTEND_ROOT,
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


def _api_compatibility_error(payload: dict[str, object], database_path: Path) -> str:
    if payload.get("service") != "Lightweight IDS local API":
        return "the service identity does not match"
    if payload.get("apiVersion") != LOCAL_API_VERSION:
        return f"expected API v{LOCAL_API_VERSION}, received {payload.get('apiVersion', 'unknown')}"
    capabilities = payload.get("capabilities")
    required = {"endpoint-security-v1", "system-health-v1", "topology-v1"}
    if not isinstance(capabilities, list) or not required.issubset({str(item) for item in capabilities}):
        return "required endpoint-security capabilities are missing"
    configured_database = payload.get("database")
    try:
        running_database = Path(str(configured_database)).resolve()
    except (OSError, TypeError, ValueError):
        return "the API did not report a valid database path"
    if running_database != database_path.resolve():
        return f"it uses {running_database}, not {database_path.resolve()}"
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
