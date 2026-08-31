from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from .core import MAX_WEBHOOK_BYTES, require_positive_int
from .github import AppTokenProvider, GitHubClient
from .service import ServiceConfig, TrustedGateService
from .store import DeliveryStore


class Handler(BaseHTTPRequestHandler):
    server_version = "YPTrustedGate/1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self._respond(HTTPStatus.NOT_FOUND, {"status": "not_found"})
            return
        self._respond(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/github/webhook":
            self._respond(HTTPStatus.NOT_FOUND, {"status": "not_found"})
            return
        if self.headers.get("Transfer-Encoding"):
            self._respond(HTTPStatus.BAD_REQUEST, {"status": "rejected"})
            return
        content_type = self.headers.get("Content-Type", "")
        user_agent = self.headers.get("User-Agent", "")
        if (
            not content_type.lower().startswith("application/json")
            or not user_agent.startswith("GitHub-Hookshot/")
        ):
            self._respond(HTTPStatus.BAD_REQUEST, {"status": "rejected"})
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "-1")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_WEBHOOK_BYTES:
            self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"status": "rejected"})
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._respond(HTTPStatus.BAD_REQUEST, {"status": "rejected"})
            return
        try:
            result = self.server.service.handle_delivery(  # type: ignore[attr-defined]
                event_header=self.headers.get("X-GitHub-Event"),
                delivery_header=self.headers.get("X-GitHub-Delivery"),
                signature_header=self.headers.get("X-Hub-Signature-256"),
                body=body,
            )
        except PermissionError:
            self._respond(HTTPStatus.UNAUTHORIZED, {"status": "rejected"})
            return
        except ValueError:
            self._respond(HTTPStatus.BAD_REQUEST, {"status": "rejected"})
            return
        status = HTTPStatus.SERVICE_UNAVAILABLE if result.outcome == "RETRYABLE" else HTTPStatus.ACCEPTED
        self._respond(
            status,
            {
                "status": result.outcome,
                "delivery_id": result.delivery_id,
                "reason": result.reason,
                "status_published": result.status_published,
            },
        )

    def log_message(self, format: str, *args: object) -> None:
        # Avoid logging webhook headers/bodies or authorization-bearing content.
        return

    def _respond(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class BoundedHTTPServer(HTTPServer):
    request_queue_size = 16

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(10.0)
        return request, client_address


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def build_service() -> TrustedGateService:
    installation_id = require_positive_int(
        int(_required_env("TRUSTED_GATE_INSTALLATION_ID")), label="installation id"
    )
    repository = _required_env("TRUSTED_GATE_REPOSITORY")
    provider = AppTokenProvider(
        app_id=_required_env("TRUSTED_GATE_APP_ID"),
        installation_id=installation_id,
        repository=repository,
        private_key_pem=_required_env("TRUSTED_GATE_APP_PRIVATE_KEY"),
        openssl_bin=os.environ.get("TRUSTED_GATE_OPENSSL_BIN", "/usr/bin/openssl"),
    )
    github = GitHubClient(token_provider=provider, installation_id=installation_id)
    store = DeliveryStore(Path(_required_env("TRUSTED_GATE_DB_PATH")))
    config = ServiceConfig(
        webhook_secret=_required_env("TRUSTED_GATE_WEBHOOK_SECRET").encode("utf-8"),
        installation_id=installation_id,
        expected_creator_login=_required_env("TRUSTED_GATE_APP_BOT_LOGIN"),
        policy_path=Path(_required_env("TRUSTED_GATE_POLICY_PATH")),
        policy_sha256=_required_env("TRUSTED_GATE_POLICY_SHA256"),
    )
    return TrustedGateService(config=config, store=store, github=github)


def main() -> None:
    service = build_service()
    host = os.environ.get("TRUSTED_GATE_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("TRUSTED_GATE_BIND_PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("TRUSTED_GATE_BIND_PORT is outside valid range")
    server = BoundedHTTPServer((host, port), Handler)
    server.service = service  # type: ignore[attr-defined]
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
