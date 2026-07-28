from __future__ import annotations

import argparse
import hmac
import json
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MAX_BODY_BYTES = 8 * 1024 * 1024


class AuditWriter:
    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self._lock = threading.Lock()

    def append(self, payload: Any) -> int:
        documents = payload if isinstance(payload, list) else [payload]
        documents = [item for item in documents if isinstance(item, dict)]
        if not documents:
            return 0
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.output_path.open("a", encoding="utf-8", newline="\n") as handle:
                for document in documents:
                    handle.write(
                        json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n"
                    )
                handle.flush()
                os.fsync(handle.fileno())
            self.output_path.chmod(0o640)
        return len(documents)


def build_handler(writer: AuditWriter, auth_token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "siem-minio-audit/1"

        def log_message(self, _format: str, *args: object) -> None:
            return

        def _json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/health":
                self._json_response(HTTPStatus.NOT_FOUND, {"status": "not_found"})
                return
            self._json_response(HTTPStatus.OK, {"status": "ok"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/audit":
                self._json_response(HTTPStatus.NOT_FOUND, {"status": "not_found"})
                return
            if auth_token:
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied, auth_token):
                    self._json_response(HTTPStatus.UNAUTHORIZED, {"status": "unauthorized"})
                    return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY_BYTES:
                self._json_response(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"status": "invalid_body"},
                )
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, ValueError):
                self._json_response(HTTPStatus.BAD_REQUEST, {"status": "invalid_json"})
                return
            written = writer.append(payload)
            if not written:
                self._json_response(HTTPStatus.BAD_REQUEST, {"status": "invalid_payload"})
                return
            self._json_response(HTTPStatus.OK, {"status": "accepted", "records": written})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Receive MinIO audit webhook records.")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9191)
    parser.add_argument("--output-path", default="/var/log/siem/minio-audit.jsonl")
    parser.add_argument("--auth-token", default=os.getenv("MINIO_AUDIT_RECEIVER_TOKEN", ""))
    args = parser.parse_args()
    writer = AuditWriter(Path(args.output_path))
    server = ThreadingHTTPServer(
        (args.listen, args.port),
        build_handler(writer, args.auth_token),
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
