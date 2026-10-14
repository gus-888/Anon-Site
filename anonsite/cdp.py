"""Cliente CDP (Chrome DevTools Protocol) via remote-debugging.

O QtWebEngine expõe o CDP em ``http://127.0.0.1:9222/json`` quando lançado
com ``--remote-debugging-port`` (ver config.chromium_flags). Este módulo
é stdlib + ``websocket-client`` (dependência pura em Python) e NÃO exige
Qt: o MCP e os testes o usam sem GUI.

Uso típico:
    client = CdpClient()
    result = client.call("Network.getAllCookies", {}, url_contains="duckduckgo")
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Any, Callable

CDP_HOST = "127.0.0.1"
CDP_PORT = 9222


def list_targets(port: int = CDP_PORT) -> list[dict[str, Any]]:
    try:
        with urllib.request.urlopen(f"http://{CDP_HOST}:{port}/json/list", timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except OSError:
        return []


def find_target(url_contains: str = "", port: int = CDP_PORT) -> dict[str, Any] | None:
    for target in list_targets(port):
        if target.get("type") != "page":
            continue
        if not url_contains or url_contains in target.get("url", ""):
            return target
    return None


class CdpClient:
    """Uma conexão websocket por chamada (simples e sem estado)."""

    def __init__(self, port: int = CDP_PORT, timeout: float = 10.0) -> None:
        self.port = port
        self.timeout = timeout

    def _ws_url_for_index(self, index: int) -> str | None:
        targets = [t for t in list_targets(self.port) if t.get("type") == "page"]
        if 0 <= index < len(targets):
            return targets[index].get("webSocketDebuggerUrl")
        return None

    def call_by_index(self, index: int, method: str, params: dict | None = None) -> dict[str, Any]:
        ws_url = self._ws_url_for_index(index)
        if not ws_url:
            raise RuntimeError(f"Nenhuma aba CDP no índice {index} (o navegador está rodando?)")
        return self.call_ws(ws_url, method, params or {})

    def call(self, method: str, params: dict | None = None, *, url_contains: str = "") -> dict[str, Any]:
        target = find_target(url_contains, self.port)
        if not target or not target.get("webSocketDebuggerUrl"):
            raise RuntimeError("Nenhum alvo CDP encontrado (o navegador está rodando?)")
        return self.call_ws(target["webSocketDebuggerUrl"], method, params or {})

    def call_ws(self, ws_url: str, method: str, params: dict | None = None) -> dict[str, Any]:
        import websocket  # import tardio: testes sem a dependência ainda importam o módulo

        ws = websocket.create_connection(ws_url, timeout=self.timeout)
        try:
            ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    if "error" in msg:
                        raise RuntimeError(f"CDP {method}: {msg['error']}")
                    return msg.get("result", {})
            raise TimeoutError(f"CDP {method}: sem resposta em {self.timeout}s")
        finally:
            ws.close()

    def evaluate(self, index: int, expression: str) -> Any:
        """Runtime.evaluate com awaitPromise + returnByValue (igual ao C++)."""
        result = self.call_by_index(
            index,
            "Runtime.evaluate",
            {"expression": expression, "awaitPromise": True, "returnByValue": True},
        )
        payload = result.get("result", {})
        if payload.get("subtype") == "error":
            raise RuntimeError(payload.get("description", "erro JS"))
        return payload.get("value")


class CdpEventListener(threading.Thread):
    """Assina Network.requestWillBeSent/responseReceived e alimenta o NetworkLog.

    Uma thread por aba seria desperdício; o listener abre um websocket por
    alvo e despacha eventos para ``on_event(tipo, params)``.
    """

    daemon = True

    def __init__(
        self,
        on_event: Callable[[str, dict[str, Any]], None],
        port: int = CDP_PORT,
        poll_seconds: float = 2.0,
    ) -> None:
        super().__init__(name="cdp-listener")
        self._on_event = on_event
        self._port = port
        self._poll = poll_seconds
        self._stop = threading.Event()
        self._seen: set[str] = set()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:  # pragma: no cover - requer navegador real
        import websocket

        while not self._stop.is_set():
            try:
                for target in list_targets(self._port):
                    ws_url = target.get("webSocketDebuggerUrl")
                    if not ws_url or ws_url in self._seen or target.get("type") != "page":
                        continue
                    self._seen.add(ws_url)
                    threading.Thread(
                        target=self._listen_one, args=(ws_url,), daemon=True
                    ).start()
            except Exception:
                pass
            self._stop.wait(self._poll)

    def _listen_one(self, ws_url: str) -> None:  # pragma: no cover
        import websocket

        try:
            ws = websocket.create_connection(ws_url, timeout=10)
            ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))
            ws.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    msg = json.loads(ws.recv())
                except Exception:
                    continue
                method = msg.get("method", "")
                if method in ("Network.requestWillBeSent", "Network.responseReceived"):
                    kind = "Request" if "requestWillBeSent" in method else "Response"
                    self._on_event(kind, msg.get("params", {}))
        except Exception:
            pass
