from __future__ import annotations

import argparse
import http.server
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlparse


def guess_type(path: Path) -> str:
    content_type, _ = mimetypes.guess_type(str(path))
    return content_type or "application/octet-stream"


class SpaPreviewHandler(http.server.BaseHTTPRequestHandler):
    dist_root: Path

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        request_path = unquote(parsed.path or "/")
        normalized = request_path[1:] if request_path.startswith("/") else request_path

        if normalized.startswith("app/"):
          normalized = normalized[4:]
        elif normalized == "app":
          normalized = ""

        candidate = (self.dist_root / normalized).resolve() if normalized else self.dist_root / "index.html"
        if not str(candidate).startswith(str(self.dist_root.resolve())):
            self.send_error(403)
            return

        if candidate.is_dir():
            candidate = candidate / "index.html"

        if candidate.exists() and candidate.is_file():
            self._write_file(candidate)
            return

        if request_path.startswith("/app"):
            self._write_file(self.dist_root / "index.html")
            return

        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _write_file(self, path: Path) -> None:
        payload = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", guess_type(path))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve frontend dist with /app SPA fallback.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4174)
    parser.add_argument("--dist", default=str(Path(__file__).resolve().parents[1] / "dist"))
    args = parser.parse_args()

    dist_root = Path(args.dist).resolve()
    if not dist_root.exists():
        raise SystemExit(f"dist root does not exist: {dist_root}")

    handler = type("BoundSpaPreviewHandler", (SpaPreviewHandler,), {"dist_root": dist_root})
    server = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving {dist_root} on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
