"""Servidor MCP (Model Context Protocol) via stdio — traducao de mcp_server.js.

Protocolo: JSON-RPC 2.0 linha a linha no stdin/stdout, como o original:
  initialize -> {protocolVersion: "2024-11-05", capabilities: {tools: {}}, ...}
  tools/list -> lista de ferramentas
  tools/call -> executa uma ferramenta

As ferramentas de navegador falam com a API HTTP do navegador em
http://127.0.0.1:8383 (o navegador precisa estar rodando com o MCP
ativado na Central). As ferramentas externas (nmap etc.) estao em
tools_external.py e rodam sem navegador.

Uso (ex.: Claude Desktop / clientes MCP):
  {"mcpServers": {"anonsite": {"command": "python", "args": ["-m", "anonsite.mcp_server"]}}}
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from .config import API_HOST, API_PORT
from . import tools_external as ext

BROWSER_API = f"http://{API_HOST}:{API_PORT}"
SERVER_INFO = {"name": "anonsite-mcp", "version": "1.0.0"}


def _api(method: str, path: str, body: dict | None = None):
    url = BROWSER_API + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"raw": raw}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}")
    except OSError as exc:
        raise RuntimeError(f"Nao foi possivel falar com o navegador em {BROWSER_API} (ele esta rodando com MCP ativado?): {exc}")


def _unwrap_cdp(res) -> str:
    """Normaliza a resposta de /execute (CDP Runtime.evaluate) para texto."""
    if isinstance(res, dict):
        result = res.get("result")
        if isinstance(result, dict):
            if result.get("subtype") == "error":
                raise RuntimeError(result.get("description", "erro JS"))
            value = result.get("value")
            return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        if "exceptionDetails" in res:
            raise RuntimeError(json.dumps(res["exceptionDetails"], ensure_ascii=False))
    return res if isinstance(res, str) else json.dumps(res, ensure_ascii=False)


def _execute(index: int, script: str) -> str:
    return _unwrap_cdp(_api("POST", "/execute", {"index": index, "script": script}))


def _cdp(index: int, method: str, params: dict | None = None):
    return _api("POST", "/cdp", {"index": index, "method": method, "params": params or {}})


def _js_str(value) -> str:
    return json.dumps(value, ensure_ascii=False)


TOOLS: list[dict] = [
    {"name": "list_tabs", "description": "Lists all open tabs in AnonSite browser, returning their index, URL, and page title.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "get_tab_html", "description": "Retrieves the full outer HTML content of a specific tab.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer", "description": "The index of the tab to get HTML from."}}, "required": ["index"]}},
    {"name": "execute_js", "description": "Executes custom JavaScript code inside the context of a specific tab and returns the evaluated result. Supports ES6 Promises (await).", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "code": {"type": "string", "description": "The JavaScript code to execute."}}, "required": ["index", "code"]}},
    {"name": "get_network_requests", "description": "Retrieves the captured network HTTP request and response log metadata from the current browser session.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "navigate_tab", "description": "Navigates a specific tab to a new URL.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}}, "required": ["index", "url"]}},
    {"name": "new_tab", "description": "Opens a new browser tab with the specified URL.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "description": "The URL to open (optional)."}}}},
    {"name": "close_tab", "description": "Closes the browser tab at the specified index.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "call_cdp_method", "description": "Calls a Chrome DevTools Protocol (CDP) method directly on a tab. Returns the raw JSON response.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "method": {"type": "string", "description": "CDP method name (e.g. Network.getCookies)"}, "params": {"type": "object"}}, "required": ["index", "method"]}},
    {"name": "get_response_body", "description": "Retrieves the full response body of a network request captured via the network log.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "requestId": {"type": "string", "description": "The requestId from the network log."}}, "required": ["index", "requestId"]}},
    {"name": "repeater_request", "description": "Simulates a Burp-Suite-style repeater request, executing a custom fetch call with specified headers, method, and body from the tab context.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}, "method": {"type": "string"}, "headers": {"type": "object"}, "body": {"type": "string"}}, "required": ["index", "url", "method"]}},
    {"name": "capture_screenshot", "description": "Captures a PNG screenshot preview of the tab's viewport and returns the local file path.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "get_cookies", "description": "Retrieves all cookies for the current tab page context.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "set_cookie", "description": "Sets a cookie in the browser profile session.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "name": {"type": "string"}, "value": {"type": "string"}, "domain": {"type": "string"}, "path": {"type": "string", "description": "Cookie path (optional, default is /)."}}, "required": ["index", "name", "value", "domain"]}},
    {"name": "fill_form_input", "description": "Fills a text input, textarea, or form field by CSS selector.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "selector": {"type": "string"}, "value": {"type": "string"}}, "required": ["index", "selector", "value"]}},
    {"name": "click_element", "description": "Clicks a button, link, or clickable element by CSS selector.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "selector": {"type": "string"}}, "required": ["index", "selector"]}},
    {"name": "submit_form", "description": "Submits a form or triggers form submission by CSS selector.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "selector": {"type": "string"}}, "required": ["index", "selector"]}},
    {"name": "delete_cookie", "description": "Deletes a specific cookie from the browser session by name and domain or URL.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "name": {"type": "string"}, "domain": {"type": "string"}, "url": {"type": "string"}}, "required": ["index", "name"]}},
    {"name": "get_storage", "description": "Retrieves all items from localStorage or sessionStorage for the active domain of a tab.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "type": {"type": "string", "enum": ["local", "session"]}}, "required": ["index", "type"]}},
    {"name": "set_storage_item", "description": "Sets or updates a key-value item in localStorage or sessionStorage.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "type": {"type": "string", "enum": ["local", "session"]}, "key": {"type": "string"}, "value": {"type": "string"}}, "required": ["index", "type", "key", "value"]}},
    {"name": "remove_storage_item", "description": "Removes a key-value item from localStorage or sessionStorage.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "type": {"type": "string", "enum": ["local", "session"]}, "key": {"type": "string"}}, "required": ["index", "type", "key"]}},
    {"name": "clear_storage", "description": "Clears all key-value entries in localStorage or sessionStorage for a tab.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "type": {"type": "string", "enum": ["local", "session"]}}, "required": ["index", "type"]}},
    {"name": "filter_network_requests", "description": "Filters captured network requests by query string, HTTP method, or status code range.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "method": {"type": "string"}, "status_code": {"type": "integer"}}}},
    {"name": "custom_raw_request", "description": "Executes a custom HTTP request with full control over headers, method, body, and credentials from tab context or server fetch.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}, "method": {"type": "string"}, "headers": {"type": "object"}, "body": {"type": "string"}}, "required": ["index", "url", "method"]}},
    {"name": "get_page_inputs_and_forms", "description": "Discovers all form elements, input fields, textareas, buttons, and hidden parameters on the current page for vulnerability assessment.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "extract_js_links_and_endpoints", "description": "Scrapes all loaded JavaScript files and inline scripts to extract API endpoints, paths, relative URLs, and potential secrets.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "fuzz_parameter", "description": "Fuzzes a target URL parameter or HTTP request body with a list of payloads to test for injection flaws (XSS, SQLi, SSRF, LFI) and compares response lengths/statuses.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}, "method": {"type": "string"}, "param_name": {"type": "string"}, "payloads": {"type": "array", "items": {"type": "string"}}, "headers": {"type": "object"}}, "required": ["index", "url", "method", "param_name", "payloads"]}},
    {"name": "test_cors_policy", "description": "Tests a target endpoint for CORS misconfigurations (Origin reflection, Allow-Credentials: true, Null Origin).", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}}, "required": ["index", "url"]}},
    {"name": "dump_session_tokens", "description": "Dumps all session state (Cookies, localStorage, sessionStorage, and Authorization headers) for complete session export.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "restore_session_state", "description": "Restores session state (Cookies, localStorage, sessionStorage) into the browser tab.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "cookies": {"type": "array", "items": {"type": "object"}}, "localStorageData": {"type": "object"}, "sessionStorageData": {"type": "object"}}, "required": ["index"]}},
    {"name": "set_custom_user_agent", "description": "Overrides the browser User-Agent string for a specific tab via CDP.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "userAgent": {"type": "string"}}, "required": ["index", "userAgent"]}},
    {"name": "set_extra_http_headers", "description": "Injects custom default HTTP request headers for all subsequent requests in a tab via CDP.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "headers": {"type": "object"}}, "required": ["index", "headers"]}},
    {"name": "get_event_listeners", "description": "Discovers active DOM and window event listeners (click, submit, message, input, etc.).", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "selector": {"type": "string", "description": "CSS selector (optional, defaults to window/document)."}}, "required": ["index"]}},
    {"name": "monitor_postmessage", "description": "Monitors window.postMessage calls to audit cross-window communication.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "action": {"type": "string", "enum": ["start", "get_logs", "clear"]}}, "required": ["index", "action"]}},
    {"name": "inspect_global_vars", "description": "Enumerate custom, non-standard global properties on the window context.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "analyze_security_headers", "description": "Audits HTTP security response headers of the current page (CSP, HSTS, X-Frame-Options, etc.).", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "decode_jwt_token", "description": "Decodes a JWT token structure without requiring an active browser tab.", "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]}},
    {"name": "get_websocket_frames", "description": "Retrieves captured WebSocket connections and messages from the network traffic log.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "list_service_workers", "description": "Lists registered Service Workers, their scopes, active scripts and status on the target tab.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "detect_technologies", "description": "Analyzes loaded scripts, DOM signatures, meta tags, and global runtime objects to fingerprint frameworks and libraries.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "download_resource_content", "description": "Fetches and returns the content of any script, stylesheet, source map (.map), or API definition file loaded in the tab context.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}, "url": {"type": "string"}}, "required": ["index", "url"]}},
    {"name": "run_nmap", "description": "Runs an Nmap port, service, and vulnerability scan against a target host, IP, or CIDR network.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "flags": {"type": "string"}, "timeout_seconds": {"type": "integer"}, "custom_path": {"type": "string"}}, "required": ["target"]}},
    {"name": "run_theharvester", "description": "Runs theHarvester for OSINT recon to gather emails, subdomains, hosts, and banners.", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "sources": {"type": "string"}, "limit": {"type": "integer"}, "flags": {"type": "string"}, "timeout_seconds": {"type": "integer"}, "custom_path": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_whatweb", "description": "Runs WhatWeb web technology identifier to fingerprint web servers, CMSs, JS libraries, and versions.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "aggression": {"type": "integer"}, "flags": {"type": "string"}, "timeout_seconds": {"type": "integer"}, "custom_path": {"type": "string"}}, "required": ["target"]}},
    {"name": "run_nuclei", "description": "Runs Nuclei vulnerability scanner against a target URL/host using community templates.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "severity": {"type": "string"}, "tags": {"type": "string"}, "templates": {"type": "string"}, "flags": {"type": "string"}, "timeout_seconds": {"type": "integer"}, "custom_path": {"type": "string"}}, "required": ["target"]}},
    {"name": "resolve_dns", "description": "Performs complete DNS lookup records (A, AAAA, MX, TXT, CNAME, NS, SOA) for a given hostname/domain.", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "record_type": {"type": "string"}}, "required": ["domain"]}},
    {"name": "subdomain_ct_logs", "description": "Queries public Certificate Transparency (CT) logs (via crt.sh) to discover subdomains and SSL certificates for a domain.", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "check_ssl_cert", "description": "Inspects TLS/SSL certificate details of a host, including issuer, validity dates, SANs, cipher, and protocol.", "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["host"]}},
    {"name": "export_har_log", "description": "Exports captured browser network traffic requests and responses in standard HTTP Archive (.har) format.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}}},
    {"name": "parse_openapi_spec", "description": "Fetches and parses an OpenAPI / Swagger JSON or YAML specification URL, extracting endpoints, methods, parameters, and schemas.", "inputSchema": {"type": "object", "properties": {"spec_url": {"type": "string"}}, "required": ["spec_url"]}},
    {"name": "trace_redirects", "description": "Traces the full HTTP redirect chain (301, 302, 307, 308) from an initial URL to the final destination.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "max_redirects": {"type": "integer"}, "user_agent": {"type": "string"}}, "required": ["url"]}},
]


def call_tool(name: str, args: dict) -> str:
    """Executa uma ferramenta e devolve texto (conteúdo de tools/call)."""
    idx = int(args.get("index", 0))
    if name == "list_tabs":
        return json.dumps(_api("GET", "/tabs"), indent=2, ensure_ascii=False)
    if name == "get_tab_html":
        return str(_api("GET", f"/html?index={idx}"))
    if name == "execute_js":
        return _execute(idx, args.get("code", ""))
    if name == "get_network_requests":
        return json.dumps(_api("GET", "/network"), indent=2, ensure_ascii=False)
    if name == "navigate_tab":
        return json.dumps(_api("POST", "/navigate", {"index": idx, "url": args["url"]}), indent=2)
    if name == "new_tab":
        return json.dumps(_api("POST", "/newtab", {"url": args.get("url", "")}), indent=2)
    if name == "close_tab":
        return json.dumps(_api("POST", "/close", {"index": idx}), indent=2)
    if name == "call_cdp_method":
        return json.dumps(_cdp(idx, args["method"], args.get("params") or {}), indent=2, ensure_ascii=False)
    if name == "get_response_body":
        return json.dumps(_cdp(idx, "Network.getResponseBody", {"requestId": args["requestId"]}), indent=2, ensure_ascii=False)
    if name in ("repeater_request", "custom_raw_request"):
        _headers_json = _js_str(args.get('headers') or {})
        script = f"""(async () => {{
            try {{
                const resp = await fetch({_js_str(args['url'])}, {{method: {_js_str(args.get('method', 'GET'))}, headers: {_headers_json}, body: {_js_str(args.get('body')) if args.get('body') is not None else 'undefined'}}});
                const text = await resp.text();
                return JSON.stringify({{status: resp.status, headers: Object.fromEntries(resp.headers.entries()), body: text.slice(0, 50000)}});
            }} catch(e) {{ return JSON.stringify({{error: e.message}}); }}
        }})()"""
        return _execute(idx, script)
    if name == "capture_screenshot":
        return json.dumps(_api("GET", f"/screenshot?index={idx}"), indent=2)
    if name == "get_cookies":
        return json.dumps(_cdp(idx, "Network.getAllCookies", {}), indent=2, ensure_ascii=False)
    if name == "set_cookie":
        params = {"name": args["name"], "value": args["value"], "domain": args["domain"], "path": args.get("path", "/")}
        return json.dumps(_cdp(idx, "Network.setCookie", params), indent=2)
    if name == "fill_form_input":
        return _execute(idx, f"""(function() {{
            const el = document.querySelector({_js_str(args['selector'])});
            if (!el) throw new Error("Element not found: " + {_js_str(args['selector'])});
            el.value = {_js_str(args['value'])};
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return "Successfully filled input";
        }})()""")
    if name == "click_element":
        return _execute(idx, f"""(function() {{
            const el = document.querySelector({_js_str(args['selector'])});
            if (!el) throw new Error("Element not found: " + {_js_str(args['selector'])});
            el.click();
            return "Successfully clicked element";
        }})()""")
    if name == "submit_form":
        return _execute(idx, f"""(function() {{
            const el = document.querySelector({_js_str(args['selector'])});
            if (!el) throw new Error("Form/Element not found: " + {_js_str(args['selector'])});
            if (el.tagName === 'FORM') {{ el.submit(); }} else {{
                const form = el.closest('form');
                if (form) {{ form.submit(); }} else {{ throw new Error("No form associated with the element"); }}
            }}
            return "Successfully submitted form";
        }})()""")
    if name == "delete_cookie":
        params = {"name": args["name"]}
        if args.get("domain"):
            params["domain"] = args["domain"]
        if args.get("url"):
            params["url"] = args["url"]
        return json.dumps(_cdp(idx, "Network.deleteCookies", params), indent=2)
    if name == "get_storage":
        target = "sessionStorage" if args.get("type") == "session" else "localStorage"
        return _execute(idx, f"""(function() {{
            const store = window.{target}; const data = {{}};
            for (let i = 0; i < store.length; i++) {{ const k = store.key(i); data[k] = store.getItem(k); }}
            return JSON.stringify(data);
        }})()""")
    if name == "set_storage_item":
        target = "sessionStorage" if args.get("type") == "session" else "localStorage"
        return _execute(idx, f"window.{target}.setItem({_js_str(args['key'])}, {_js_str(args['value'])}); 'ok';")
    if name == "remove_storage_item":
        target = "sessionStorage" if args.get("type") == "session" else "localStorage"
        return _execute(idx, f"window.{target}.removeItem({_js_str(args['key'])}); 'ok';")
    if name == "clear_storage":
        target = "sessionStorage" if args.get("type") == "session" else "localStorage"
        return _execute(idx, f"window.{target}.clear(); 'ok';")
    if name == "filter_network_requests":
        entries = _api("GET", "/network") or []
        out = []
        for e in entries:
            data = e.get("data") or {}
            req, resp = data.get("request") or {}, data.get("response") or {}
            if args.get("method") and (req.get("method") or "").upper() != args["method"].upper():
                continue
            if args.get("status_code") is not None and resp.get("status") != args["status_code"]:
                continue
            if args.get("query"):
                hay = json.dumps(e, ensure_ascii=False).lower()
                if args["query"].lower() not in hay:
                    continue
            out.append(e)
        return json.dumps(out, indent=2, ensure_ascii=False)
    if name == "get_page_inputs_and_forms":
        return _execute(idx, """(function() {
            const pick = (els, fn) => Array.from(els).map(fn);
            return JSON.stringify({
                forms: pick(document.forms, f => ({action: f.action, method: f.method, id: f.id, name: f.name})),
                inputs: pick(document.querySelectorAll('input'), e => ({type: e.type, name: e.name, id: e.id, placeholder: e.placeholder, value: e.value})),
                textareas: pick(document.querySelectorAll('textarea'), e => ({name: e.name, id: e.id})),
                selects: pick(document.querySelectorAll('select'), e => ({name: e.name, id: e.id})),
                buttons: pick(document.querySelectorAll('button, input[type=submit], input[type=button]'), e => ({text: (e.innerText||e.value||'').trim(), type: e.type}))
            });
        })()""")
    if name == "extract_js_links_and_endpoints":
        return _execute(idx, """(async () => {
            const urls = new Set();
            document.querySelectorAll('script[src]').forEach(s => urls.add(s.src));
            document.querySelectorAll('link[href]').forEach(l => urls.add(l.href));
            const urlRegex = /["'`](\\/[^\\s"'`]+(?:\\?[\\w=&%+-]*)?)["'`]/g;
            let m; const html = document.documentElement.outerHTML;
            while ((m = urlRegex.exec(html)) !== null) { urls.add(m[1]); }
            return JSON.stringify({scripts: Array.from(urls)});
        })()""")
    if name == "fuzz_parameter":
        _headers_json = _js_str(args.get('headers') or {})
        script = f"""(async () => {{
            const results = [];
            for (const payload of {_js_str(args['payloads'])}) {{
                const url = new URL({_js_str(args['url'])}, window.location.origin);
                if ({_js_str(args.get('method', 'GET'))}.toUpperCase() === 'GET') {{
                    url.searchParams.set({_js_str(args['param_name'])}, payload);
                    const r = await fetch(url.toString(), {{headers: {_headers_json}}});
                    const t = await r.text();
                    results.push({{payload, status: r.status, length: t.length}});
                }} else {{
                    const body = new URLSearchParams(); body.set({_js_str(args['param_name'])}, payload);
                    const r = await fetch({_js_str(args['url'])}, {{method: {_js_str(args.get('method', 'POST'))}, headers: {_headers_json}, body: body.toString()}});
                    const t = await r.text();
                    results.push({{payload, status: r.status, length: t.length}});
                }}
            }}
            return JSON.stringify(results);
        }})()"""
        return _execute(idx, script)
    if name == "test_cors_policy":
        script = f"""(async () => {{
            const out = [];
            for (const origin of ['https://evil.com', 'null', window.location.origin]) {{
                try {{
                    const r = await fetch({_js_str(args['url'])}, {{headers: {{Origin: origin}}, mode: 'cors'}});
                    out.push({{origin, status: r.status, acao: r.headers.get('access-control-allow-origin'), creds: r.headers.get('access-control-allow-credentials')}});
                }} catch(e) {{ out.push({{origin, error: e.message}}); }}
            }}
            return JSON.stringify(out);
        }})()"""
        return _execute(idx, script)
    if name == "dump_session_tokens":
        cookies = _cdp(idx, "Network.getAllCookies", {})
        local = _execute(idx, "(function(){const o={};for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o[k]=localStorage.getItem(k);}return JSON.stringify(o);})()")
        session = _execute(idx, "(function(){const o={};for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k);}return JSON.stringify(o);})()")
        net = _api("GET", "/network") or []
        auth = [e for e in net if "authorization" in json.dumps(e, ensure_ascii=False).lower()]
        return json.dumps({"cookies": cookies, "localStorage": local, "sessionStorage": session, "authHeaders": auth}, indent=2, ensure_ascii=False)
    if name == "restore_session_state":
        for cookie in args.get("cookies") or []:
            _cdp(idx, "Network.setCookie", cookie)
        if args.get("localStorageData"):
            _execute(idx, f"(function(){{let d={_js_str(args['localStorageData'])};for(let k in d) localStorage.setItem(k, d[k]);}})();")
        if args.get("sessionStorageData"):
            _execute(idx, f"(function(){{let d={_js_str(args['sessionStorageData'])};for(let k in d) sessionStorage.setItem(k, d[k]);}})();")
        return json.dumps({"status": "ok"})
    if name == "set_custom_user_agent":
        return json.dumps(_cdp(idx, "Network.setUserAgentOverride", {"userAgent": args["userAgent"]}), indent=2)
    if name == "set_extra_http_headers":
        return json.dumps(_cdp(idx, "Network.setExtraHTTPHeaders", {"headers": args.get("headers") or {}}), indent=2)
    if name == "get_event_listeners":
        sel = args.get("selector") or ""
        return _execute(idx, f"""(function() {{
            const el = {_js_str(sel) or 'null'} ? document.querySelector({_js_str(sel)}) : window;
            if (!el && {_js_str(sel) or 'null'}) return JSON.stringify({{error: 'Element not found'}});
            const out = {{}};
            for (const k in el) {{ if (k.startsWith('on') && el[k]) out[k] = typeof el[k]; }}
            if (window.getEventListeners) {{ try {{ out.getEventListeners = window.getEventListeners(el); }} catch(e) {{}} }}
            return JSON.stringify(out);
        }})()""")
    if name == "monitor_postmessage":
        action = args.get("action")
        if action == "start":
            return _execute(idx, """(function(){ window.__PM_LOGS__ = window.__PM_LOGS__ || [];
                if (!window.__PM_HOOKED__) { window.__PM_HOOKED__ = true;
                    window.addEventListener('message', e => { window.__PM_LOGS__.push({origin: e.origin, data: String(e.data).slice(0,2000), time: new Date().toISOString()}); }); }
                return 'postMessage monitoring started'; })()""")
        if action == "get_logs":
            return _execute(idx, "JSON.stringify(window.__PM_LOGS__ || []);")
        if action == "clear":
            return _execute(idx, "window.__PM_LOGS__ = []; 'cleared';")
        raise ValueError("action deve ser start/get_logs/clear")
    if name == "inspect_global_vars":
        return _execute(idx, """(function() {
            const standard = new Set(['window','document','navigator','location','history','screen','localStorage','sessionStorage','fetch','console','setTimeout','clearTimeout','setInterval','clearInterval','alert','confirm','prompt','print','postMessage','btoa','atob','XMLHttpRequest','WebSocket','Event','CustomEvent','Promise','Map','Set','JSON','Math','Date','Array','Object']);
            const out = {};
            for (const k of Object.keys(window)) { if (!standard.has(k)) { try { out[k] = typeof window[k]; } catch(e) { out[k] = 'inaccessible'; } } }
            return JSON.stringify(out);
        })()""")
    if name == "analyze_security_headers":
        return _execute(idx, """(async () => {
            const resp = await fetch(window.location.href, {method: 'HEAD'});
            const h = {}; resp.headers.forEach((v, k) => h[k] = v);
            const checks = {csp: !!h['content-security-policy'], hsts: !!h['strict-transport-security'], xFrame: !!h['x-frame-options'], xContentType: !!h['x-content-type-options'], referrerPolicy: !!h['referrer-policy'], permissionsPolicy: !!h['permissions-policy']};
            return JSON.stringify({headers: h, checks});
        })()""")
    if name == "decode_jwt_token":
        return ext.decode_jwt_token(args["token"])
    if name == "get_websocket_frames":
        entries = _api("GET", "/network") or []
        out = [e for e in entries if "websocket" in json.dumps(e, ensure_ascii=False).lower() or (e.get("data") or {}).get("type", "").lower().startswith("websocket")]
        return json.dumps(out, indent=2, ensure_ascii=False)
    if name == "list_service_workers":
        return _execute(idx, """(async () => {
            if (!navigator.serviceWorker) return JSON.stringify({error: 'Service Workers nao suportados'});
            const regs = await navigator.serviceWorker.getRegistrations();
            return JSON.stringify(await Promise.all(regs.map(async r => ({scope: r.scope, active: r.active ? {scriptURL: r.active.scriptURL, state: r.active.state} : null, installing: !!r.installing, waiting: !!r.waiting}))));
        })()""")
    if name == "detect_technologies":
        return _execute(idx, """(function() {
            const techs = [];
            if (window.React || document.querySelector('[data-reactroot]')) techs.push({name: 'React', category: 'Frontend Framework'});
            if (window.Vue) techs.push({name: 'Vue.js', category: 'Frontend Framework'});
            if (window.angular || document.querySelector('[ng-app]')) techs.push({name: 'Angular', category: 'Frontend Framework'});
            if (window.jQuery) techs.push({name: 'jQuery', version: window.jQuery.fn.jquery, category: 'JavaScript Library'});
            if (window.bootstrap) techs.push({name: 'Bootstrap', category: 'UI Framework'});
            if (window.webpackChunk || window.__webpack_require__) techs.push({name: 'Webpack', category: 'Module Bundler'});
            if (window.Alpine) techs.push({name: 'Alpine.js', category: 'Frontend Framework'});
            if (window.TailwindCSS || document.querySelector('[class*="bg-"], [class*="text-"], [class*="flex-"]')) techs.push({name: 'Tailwind CSS', category: 'CSS Framework'});
            const metaGenerator = document.querySelector('meta[name="generator"]');
            if (metaGenerator) techs.push({name: metaGenerator.content, category: 'CMS / Generator'});
            return JSON.stringify(techs);
        })()""")
    if name == "download_resource_content":
        return _execute(idx, f"""(async () => {{
            try {{
                const resp = await fetch({_js_str(args['url'])});
                const text = await resp.text();
                return JSON.stringify({{url: {_js_str(args['url'])}, status: resp.status, contentLength: text.length, content: text.length > 50000 ? text.slice(0, 50000) + "\\n... [TRUNCATED DUE TO SIZE]" : text}});
            }} catch(e) {{ return JSON.stringify({{url: {_js_str(args['url'])}, error: e.message}}); }}
        }})()""")
    if name == "run_nmap":
        return ext.run_nmap(args["target"], args.get("flags") or "-sV -T4 -F", int(args.get("timeout_seconds") or 120), args.get("custom_path"))
    if name == "run_theharvester":
        return ext.run_theharvester(args["domain"], args.get("sources") or "all", int(args.get("limit") or 500), args.get("flags") or "", int(args.get("timeout_seconds") or 180), args.get("custom_path"))
    if name == "run_whatweb":
        return ext.run_whatweb(args["target"], int(args.get("aggression") or 1), args.get("flags") or "", int(args.get("timeout_seconds") or 120), args.get("custom_path"))
    if name == "run_nuclei":
        return ext.run_nuclei(args["target"], args.get("severity"), args.get("tags"), args.get("templates"), args.get("flags") or "", int(args.get("timeout_seconds") or 300), args.get("custom_path"))
    if name == "resolve_dns":
        return ext.resolve_dns(args["domain"], args.get("record_type") or "ALL")
    if name == "subdomain_ct_logs":
        return ext.subdomain_ct_logs(args["domain"])
    if name == "check_ssl_cert":
        return ext.check_ssl_cert(args["host"], int(args.get("port") or 443))
    if name == "export_har_log":
        entries = _api("GET", "/network") or []
        return ext.export_har_log(entries)
    if name == "parse_openapi_spec":
        return ext.parse_openapi_spec(args["spec_url"])
    if name == "trace_redirects":
        return ext.trace_redirects(args["url"], int(args.get("max_redirects") or 10), args.get("user_agent"))
    raise ValueError(f"Ferramenta desconhecida: {name}")


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def handle_request(req: dict) -> dict | None:
    req_id = req.get("id")
    method = req.get("method")
    if req_id is None:
        return None  # notificacao: sem resposta
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        try:
            text = call_tool(params.get("name", ""), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}}
        except Exception as exc:  # noqa: BLE001
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Erro: {exc}"}], "isError": True}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        try:
            resp = handle_request(req)
        except Exception as exc:  # noqa: BLE001
            resp = {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32603, "message": str(exc)}}
        if resp is not None:
            _send(resp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
