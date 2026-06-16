from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest

from deploy.eps_ladder_live import _web_smoke


class WebSmokeTests(unittest.TestCase):
    def test_web_smoke_records_status_and_latency(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = _web_smoke(
                base_url=f"http://127.0.0.1:{server.server_address[1]}",
                paths=["/health", "api/health/transport"],
                timeout_sec=2.0,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(result["enabled"])
        self.assertTrue(result["ok"])
        self.assertEqual([item["status"] for item in result["items"]], [200, 200])
        self.assertGreaterEqual(result["p95_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
