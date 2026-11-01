"""Serve the interface on 127.0.0.1 only, so nothing is reachable from outside.

The Host and Content-Type checks stop a website open in the same browser from
driving this server.
"""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from utxo_sleuth.ui.jobs import JobManager, labels_status

DEFAULT_PORT = 8765
PORT_ATTEMPTS = 10
MAX_BODY = 1_000_000
PAGE = Path(__file__).with_name("index.html")


class Handler(BaseHTTPRequestHandler):
    server: "InterfaceServer"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        if not self._host_allowed():
            return
        if self.path == "/":
            self._send(HTTPStatus.OK, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            self._json({"labels": labels_status()})
        elif self.path.startswith("/api/jobs/"):
            self._job_view(self.path.removeprefix("/api/jobs/"))
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._host_allowed():
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self._json({"error": "JSON only"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json({"error": "too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json({"error": "invalid JSON"}, HTTPStatus.BAD_REQUEST)
            return
        if self.path == "/api/jobs":
            job = self.server.jobs.start(str(body.get("kind")), body.get("params") or {})
            if job is None:
                self._json({"error": "unknown kind"}, HTTPStatus.BAD_REQUEST)
            else:
                self._json(job.view())
        elif self.path.endswith("/cancel"):
            job = self.server.jobs.get(self.path.split("/")[-2])
            if job is not None:
                job.cancel.set()
            self._json({"ok": job is not None})
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _job_view(self, job_id: str) -> None:
        job = self.server.jobs.get(job_id)
        if job is None:
            self._json({"error": "unknown job"}, HTTPStatus.NOT_FOUND)
        else:
            self._json(job.view())

    def _host_allowed(self) -> bool:
        port = self.server.server_address[1]
        if self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return True
        self._json({"error": "forbidden host"}, HTTPStatus.FORBIDDEN)
        return False

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(status, json.dumps(value).encode("utf-8"), "application/json")

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


class InterfaceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, jobs: JobManager | None = None) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.jobs = jobs or JobManager()


def bind(port: int) -> InterfaceServer:
    for candidate in range(port, port + PORT_ATTEMPTS):
        try:
            return InterfaceServer(candidate)
        except OSError:
            continue
    raise OSError(f"no free port between {port} and {port + PORT_ATTEMPTS - 1}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="utxo-sleuth-ui")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    server = bind(args.port)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"utxo-sleuth : {url} (Ctrl+C pour arrêter)")
    if not args.no_browser:
        threading.Timer(0.3, webbrowser.open, (url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
