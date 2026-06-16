from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

from spa_preview_server import SpaPreviewHandler
from verify_app_ui import verify

import http.server
import asyncio


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve dist and run Playwright UI verification.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4174)
    parser.add_argument("--dist", default=str(Path(__file__).resolve().parents[1] / "dist"))
    args = parser.parse_args()

    dist_root = Path(args.dist).resolve()
    handler = type("BoundSpaPreviewHandler", (SpaPreviewHandler,), {"dist_root": dist_root})
    server = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(1.0)
    try:
        asyncio.run(verify(f"http://{args.host}:{args.port}"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
