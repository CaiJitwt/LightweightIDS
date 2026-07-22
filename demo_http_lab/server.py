from __future__ import annotations

from collections import defaultdict, deque
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Callable, Iterable
from urllib.parse import urlparse

from demo_http_lab.packet_emitter import PacketEmissionError, PacketEmissionResult
from demo_http_lab.scenarios import SCENARIO_BY_ID


STATIC_ROOT = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class DemoHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        token: str = "",
        allowed_networks: Iterable[str] = (),
        max_body_bytes: int = 4_096,
        requests_per_minute: int = 30,
        packet_emitter: Callable[[str, bytes], PacketEmissionResult] | None = None,
    ) -> None:
        super().__init__(address, DemoRequestHandler)
        self.token = token
        self.allowed_networks = tuple(ipaddress.ip_network(item, strict=False) for item in allowed_networks)
        self.max_body_bytes = max(1, max_body_bytes)
        self.requests_per_minute = max(1, requests_per_minute)
        self.packet_emitter = packet_emitter
        self._request_times: dict[str, deque[float]] = defaultdict(deque)
        self._accepted_requests = 0
        self._lock = Lock()

    def client_is_allowed(self, address: str) -> bool:
        try:
            client = ipaddress.ip_address(address)
        except ValueError:
            return False
        if isinstance(client, ipaddress.IPv6Address) and client.ipv4_mapped:
            client = client.ipv4_mapped
        if self.allowed_networks:
            return any(client in network for network in self.allowed_networks if client.version == network.version)
        return client.is_private or client.is_loopback or client.is_link_local

    def accept_rate_limit(self, address: str) -> bool:
        now = monotonic()
        with self._lock:
            entries = self._request_times[address]
            while entries and now - entries[0] >= 60:
                entries.popleft()
            if len(entries) >= self.requests_per_minute:
                return False
            entries.append(now)
            return True

    def record_accepted_request(self) -> int:
        with self._lock:
            self._accepted_requests += 1
            return self._accepted_requests


class DemoRequestHandler(BaseHTTPRequestHandler):
    server: DemoHttpServer
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if not self._allow_private_client():
            return
        path = urlparse(self.path).path
        static_file = STATIC_FILES.get(path)
        if static_file is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return
        filename, content_type = static_file
        content = (STATIC_ROOT / filename).read_bytes()
        self._send_bytes(HTTPStatus.OK, content, content_type)

    def do_POST(self) -> None:  # noqa: N802
        if not self._allow_private_client():
            return

        path = urlparse(self.path).path
        prefix = "/sink/"
        scenario_id = path.removeprefix(prefix) if path.startswith(prefix) else ""
        if scenario_id not in SCENARIO_BY_ID and scenario_id != "custom":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown demo scenario."})
            return

        content_length = self._content_length()
        if content_length is None:
            return
        if content_length > self.server.max_body_bytes:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": f"Payload exceeds the {self.server.max_body_bytes}-byte demo limit."},
            )
            return

        # The body is retained only long enough to encapsulate one inert local demo frame.
        # It is never executed, persisted, reflected, or forwarded to a remote target.
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Incomplete request body."})
            return
        if not self._authorize():
            return
        if not self.server.accept_rate_limit(self.client_address[0]):
            self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Demo request rate limit reached."})
            return

        emission: PacketEmissionResult | None = None
        if self.server.packet_emitter is not None:
            try:
                emission = self.server.packet_emitter(scenario_id, body)
            except PacketEmissionError as exc:
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return

        sequence = self.server.record_accepted_request()
        result: dict[str, object] = {
            "accepted": True,
            "sequence": sequence,
            "scenario": scenario_id,
            "receivedBytes": content_length,
            "emitted": False,
            "message": "Payload received and discarded without processing.",
        }
        if emission is not None:
            result.update(emission.as_payload())
            result["message"] = "An inert HTTP frame was injected for normal live-capture analysis."
        self._send_json(HTTPStatus.ACCEPTED, result)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _allow_private_client(self) -> bool:
        if self.server.client_is_allowed(self.client_address[0]):
            return True
        self._send_json(HTTPStatus.FORBIDDEN, {"error": "Only approved private-network clients are allowed."})
        return False

    def _authorize(self) -> bool:
        if not self.server.token:
            return True
        provided = self.headers.get("X-Demo-Token", "")
        if provided and compare_digest(provided, self.server.token):
            return True
        self._send_json(HTTPStatus.FORBIDDEN, {"error": "A valid X-Demo-Token header is required."})
        return False

    def _content_length(self) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None:
            self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required."})
            return None
        try:
            value = int(raw)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length must be an integer."})
            return None
        if value < 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length cannot be negative."})
            return None
        return value

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        self._send_bytes(status, json.dumps(payload, separators=(",", ":")).encode(), "application/json")

    def _send_bytes(self, status: HTTPStatus, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(content)
