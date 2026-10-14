import json
import threading

from anonsite.api_server import start_api_server
from anonsite.mcp_server import TOOLS, handle_request
from anonsite.network_log import NetworkLog
from anonsite.tools_external import decode_jwt_token


class FakeBridge:
    def __init__(self):
        self.tabs = [{"index": 0, "url": "https://example.com", "title": "Example"}]

    def submit(self, op, payload=None):
        payload = payload or {}
        if op == "list_tabs":
            return True, self.tabs
        if op == "get_html":
            return True, "<html></html>"
        if op == "execute_js":
            return True, {"result": {"value": "ok"}}
        if op in ("navigate", "new_tab", "close_tab"):
            return True, {"status": "ok"}
        if op == "cdp":
            return True, {"cookies": []}
        if op == "screenshot":
            return True, "/tmp/AnonScreenshot_1.png"
        return False, "unknown op"


def test_api_endpoints():
    log = NetworkLog()
    log.log("Request", {"request": {"url": "https://example.com"}})
    server, _ = start_api_server("127.0.0.1", 0, bridge=FakeBridge(), network_log=log)
    port = server.server_address[1]
    import urllib.request

    def get(path):
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return json.loads(r.read())

    def post(path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    try:
        assert get("/tabs")[0]["url"] == "https://example.com"
        assert get("/html?index=0") == "<html></html>"
        assert len(get("/network")) == 1
        assert get("/screenshot?index=0")["screenshot_path"].endswith(".png")
        assert post("/execute", {"index": 0, "script": "1+1"})["result"]["value"] == "ok"
        assert post("/navigate", {"index": 0, "url": "https://example.com"}) == {"status": "ok"}
        assert post("/newtab", {"url": "https://example.com"}) == {"status": "ok"}
        assert post("/close", {"index": 0}) == {"status": "ok"}
        assert post("/cdp", {"index": 0, "method": "Network.getAllCookies", "params": {}}) == {"cookies": []}
    finally:
        server.shutdown()
        server.server_close()


def test_mcp_tools_list_has_all_original_tools():
    names = {t["name"] for t in TOOLS}
    assert len(names) == len(TOOLS)  # sem duplicatas
    for expected in ("list_tabs", "execute_js", "call_cdp_method", "run_nmap", "run_nuclei", "resolve_dns", "decode_jwt_token", "trace_redirects", "export_har_log", "monitor_postmessage"):
        assert expected in names


def test_mcp_initialize_and_tools_list():
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["result"]["serverInfo"]["name"] == "anonsite-mcp"
    resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(resp["result"]["tools"]) == len(TOOLS)


def test_mcp_decode_jwt_without_browser():
    # token com header {"alg":"HS256"} e payload {"sub":"123","exp":2000000000}
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjIwMDAwMDAwMDB9.sig"
    resp = handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "decode_jwt_token", "arguments": {"token": token}}})
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["payload"]["sub"] == "123"
    assert payload["algorithm"] == "HS256"


def test_decode_jwt_direct():
    out = json.loads(decode_jwt_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"))
    assert out["payload"]["sub"] == "123"
