"""API HTTP do navegador em 127.0.0.1:8383 — tradução do McpServerThread do C++.

Rotas (idênticas às do original):
    GET  /tabs                  -> lista de abas
    GET  /html?index=N          -> outerHTML da aba
    POST /execute               -> {index, script} via CDP Runtime.evaluate
    POST /navigate              -> {index, url}
    POST /newtab                -> {url}
    POST /close                 -> {index}
    GET  /network                -> log de rede (200 entradas)
    POST /cdp                    -> {index, method, params} CDP cru
    GET  /screenshot?index=N    -> {"screenshot_path": ...}

Diferenças em relação ao C++ (correções, não mudanças de contrato):
- o corpo JSON é parseado com ``json`` (o C++ fazia ``find("\"script\"")``
  e cortava na primeira aspa — scripts com aspas quebravam);
- a leitura do socket respeita Content-Length (o C++ lia um único recv
  de 8 KB e truncava corpos grandes).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .config import API_HOST, API_PORT


def make_handler(bridge, network_log):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silencia o log do http.server
            pass

        # -- helpers --
        def _send_json(self, status: int, payload) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

        def _bridge(self, op: str, payload: dict | None = None):
            if bridge is None:
                return False, "navegador não está rodando (bridge indisponível)"
            return bridge.submit(op, payload or {})

        # -- rotas --
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            index = int(qs.get("index", ["0"])[0] or 0)
            if parsed.path == "/tabs":
                ok, res = self._bridge("list_tabs")
                self._send_json(200 if ok else 500, res if ok else {"error": res})
            elif parsed.path == "/html":
                ok, res = self._bridge("get_html", {"index": index})
                self._send_json(200 if ok else 500, res if ok else {"error": "Failed to get HTML"})
            elif parsed.path == "/network":
                self._send_json(200, network_log.snapshot() if network_log else [])
            elif parsed.path == "/screenshot":
                ok, res = self._bridge("screenshot", {"index": index})
                self._send_json(
                    200 if ok else 500,
                    {"screenshot_path": res} if ok else {"error": "Failed to capture screenshot"},
                )
            else:
                self._send_json(404, {"error": "Not Found"})

        def do_POST(self):  # noqa: N802
            body = self._read_json()
            path = urlparse(self.path).path
            if path == "/execute":
                ok, res = self._bridge("execute_js", {"index": int(body.get("index", 0)), "script": body.get("script", "")})
                self._send_json(200 if ok else 500, res if ok else {"error": "Failed to execute script"})
            elif path == "/navigate":
                ok, _ = self._bridge("navigate", {"index": int(body.get("index", 0)), "url": body.get("url", "")})
                self._send_json(200 if ok else 500, {"status": "ok"} if ok else {"error": "Failed to navigate"})
            elif path == "/newtab":
                ok, _ = self._bridge("new_tab", {"url": body.get("url", "")})
                self._send_json(200 if ok else 500, {"status": "ok"} if ok else {"error": "Failed to open new tab"})
            elif path == "/close":
                ok, _ = self._bridge("close_tab", {"index": int(body.get("index", 0))})
                self._send_json(200 if ok else 500, {"status": "ok"} if ok else {"error": "Failed to close tab"})
            elif path == "/cdp":
                ok, res = self._bridge(
                    "cdp",
                    {"index": int(body.get("index", 0)), "method": body.get("method", ""), "params": body.get("params") or {}},
                )
                self._send_json(200 if ok else 500, res if ok else {"error": "Failed to call CDP method"})
            else:
                self._send_json(404, {"error": "Not Found"})

        def do_OPTIONS(self):  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


def start_api_server(host: str = API_HOST, port: int = API_PORT, bridge=None, network_log=None):
    """Sobe o servidor em thread daemon. Devolve (server, thread)."""
    if bridge is None or network_log is None:
        from .browser import BRIDGE, NETWORK_LOG

        bridge = bridge or BRIDGE
        network_log = network_log or NETWORK_LOG
    server = ThreadingHTTPServer((host, port), make_handler(bridge, network_log))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="anonsite-api", daemon=True)
    thread.start()
    return server, thread
