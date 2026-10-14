"""Ferramentas externas do MCP que NAO dependem do navegador.

No original (mcp_server.js) estas rodavam com exec(cmdString) - string
de shell com interpolacao direta dos argumentos (injecao de comandos).
Aqui tudo roda com subprocess.run([...]) sem shell, e flags livres sao
quebradas com shlex.split.
"""
from __future__ import annotations

import base64
import json
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


def _run_cli(binary: str, args: list[str], timeout: int, custom_path: str | None = None,
             extra_paths: list[str] | None = None, not_found_msg: str = "") -> str:
    exe = None
    if custom_path and Path(custom_path).exists():
        exe = custom_path
    else:
        for candidate in (extra_paths or []):
            if Path(candidate).exists():
                exe = candidate
                break
    if exe is None:
        exe = shutil.which(binary) or binary
    cmd = [exe] + args
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        return json.dumps({"error": not_found_msg or f"Executavel nao encontrado: {binary}", "command": cmd, "details": str(exc)}, indent=2, ensure_ascii=False)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Timeout de {timeout}s", "command": cmd}, indent=2, ensure_ascii=False)
    duration_ms = int((time.time() - started) * 1000)
    return json.dumps(
        {"command": cmd, "durationMs": duration_ms, "stdout": proc.stdout or "", "stderr": proc.stderr or "", "exitCode": proc.returncode},
        indent=2, ensure_ascii=False,
    )


def run_nmap(target: str, flags: str = "-sV -T4 -F", timeout_seconds: int = 120, custom_path: str | None = None) -> str:
    if not target:
        raise ValueError("Parameter 'target' is required.")
    extra = [
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
        "C:\\nmap\\nmap.exe",
    ]
    return _run_cli("nmap", shlex.split(flags) + [target], timeout_seconds, custom_path, extra,
                    "Nmap nao encontrado. Instale o Nmap e coloque no PATH ou informe 'custom_path'.")


def run_theharvester(domain: str, sources: str = "all", limit: int = 500, flags: str = "", timeout_seconds: int = 180, custom_path: str | None = None) -> str:
    if not domain:
        raise ValueError("Parameter 'domain' is required.")
    exe = custom_path or shutil.which("theHarvester")
    if exe and exe.endswith(".py"):
        cmd = [sys.executable, exe, "-d", domain, "-b", sources, "-l", str(limit)] + shlex.split(flags)
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except FileNotFoundError as exc:
            return json.dumps({"error": "theHarvester nao encontrado.", "command": cmd, "details": str(exc)}, indent=2)
        return json.dumps({"command": cmd, "durationMs": int((time.time() - started) * 1000), "stdout": proc.stdout, "stderr": proc.stderr, "exitCode": proc.returncode}, indent=2)
    return _run_cli("theHarvester", ["-d", domain, "-b", sources, "-l", str(limit)] + shlex.split(flags),
                    timeout_seconds, custom_path,
                    ["C:\\theHarvester\\theHarvester.py", "C:\\Python311\\Scripts\\theHarvester.exe", "C:\\Python310\\Scripts\\theHarvester.exe"],
                    "theHarvester nao encontrado. Instale (ex.: 'pip install theHarvester') e coloque no PATH ou informe 'custom_path'.")


def run_whatweb(target: str, aggression: int = 1, flags: str = "", timeout_seconds: int = 120, custom_path: str | None = None) -> str:
    if not target:
        raise ValueError("Parameter 'target' is required.")
    return _run_cli("whatweb", ["-a", str(aggression), target] + shlex.split(flags), timeout_seconds, custom_path,
                    ["C:\\whatweb\\whatweb", "C:\\Ruby31-x64\\bin\\whatweb"],
                    "WhatWeb nao encontrado. Instale o WhatWeb e coloque no PATH ou informe 'custom_path'.")


def run_nuclei(target: str, severity: str | None = None, tags: str | None = None, templates: str | None = None,
               flags: str = "", timeout_seconds: int = 300, custom_path: str | None = None) -> str:
    if not target:
        raise ValueError("Parameter 'target' is required.")
    args = ["-u", target]
    if severity:
        args += ["-severity", severity]
    if tags:
        args += ["-tags", tags]
    if templates:
        args += ["-t", templates]
    args += shlex.split(flags)
    return _run_cli("nuclei", args, timeout_seconds, custom_path,
                    ["C:\\Program Files\\nuclei\\nuclei.exe", "C:\\nuclei\\nuclei.exe"],
                    "Nuclei nao encontrado. Baixe em github.com/projectdiscovery/nuclei e coloque no PATH ou informe 'custom_path'.")


def resolve_dns(domain: str, record_type: str = "ALL") -> str:
    """DNS: A/AAAA/MX/TXT/CNAME/NS/SOA via consulta DNS crua (RFC 1035) UDP.

    O Node usava dns.resolve*. A stdlib do Python nao expoe MX/TXT/NS/SOA
    sem dnspython; por isso o pacote DNS e montado e parseado a mao.
    """
    import struct

    rec = (record_type or "ALL").upper()

    def _qtype(name: str) -> int:
        return {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}.get(name, 1)

    def _decode_name(msg: bytes, offset: int) -> str:
        labels, jumped = [], False
        while True:
            ln = msg[offset]
            if ln == 0:
                break
            if ln & 0xC0 == 0xC0:
                offset = struct.unpack(">H", msg[offset:offset + 2])[0] & 0x3FFF
                jumped = True
                continue
            labels.append(msg[offset + 1:offset + 1 + ln].decode(errors="replace"))
            offset += 1 + ln
        return ".".join(labels)

    def _raw_query(hostname: str, qtype: int) -> list[Any]:
        txid = 0x1234
        header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(p)]) + p.encode() for p in hostname.rstrip(".").split(".")) + b"\x00"
        packet = header + qname + struct.pack(">HH", qtype, 1)
        data = b""
        for server in ("8.8.8.8", "1.1.1.1"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(packet, (server, 53))
                data, _ = sock.recvfrom(4096)
                sock.close()
                break
            except OSError:
                continue
        if not data:
            return []
        ancount = struct.unpack(">H", data[6:8])[0]
        off = 12
        while off < len(data) and data[off] != 0:
            off += 1 + data[off]
        off += 5
        answers: list[Any] = []
        for _ in range(ancount):
            if off + 10 > len(data):
                break
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += 1 + data[off]
                off += 1
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            rdata_off = off
            off += rdlen
            if rtype != qtype:
                continue
            if qtype == 1 and len(rdata) == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif qtype == 28 and len(rdata) == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif qtype in (2, 5):
                answers.append(_decode_name(data, rdata_off))
            elif qtype == 15 and len(rdata) >= 3:
                pref = struct.unpack(">H", rdata[:2])[0]
                answers.append({"preference": pref, "exchange": _decode_name(data, rdata_off + 2)})
            elif qtype == 16:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln].decode(errors="replace"))
                    i += 1 + ln
                answers.append("".join(parts))
            elif qtype == 6:
                answers.append({"raw": rdata.hex()})
        return answers

    try:
        results: dict[str, Any] = {}
        for name in ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"):
            if rec in ("ALL", name):
                try:
                    results[name] = _raw_query(domain, _qtype(name))
                except Exception as exc:  # noqa: BLE001
                    results[name] = str(exc)
        return json.dumps({"domain": domain, "records": results}, indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"domain": domain, "error": str(exc)})


def subdomain_ct_logs(domain: str) -> str:
    from urllib.parse import quote

    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"domain": domain, "error": str(exc)})
    subs: set[str] = set()
    for entry in parsed:
        for sub in (entry.get("name_value") or "").split("\n"):
            sub = sub.strip()
            if sub:
                subs.add(sub)
    return json.dumps({"domain": domain, "total": len(subs), "subdomains": sorted(subs)}, indent=2, ensure_ascii=False)


def check_ssl_cert(host: str, port: int = 443) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"host": host, "error": str(exc)})
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        parsed = x509.load_der_x509_certificate(cert_der, default_backend())
        import datetime

        subject = {a.oid._name: a.value for a in parsed.subject}
        issuer = {a.oid._name: a.value for a in parsed.issuer}
        san: list[str] = []
        try:
            san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:  # noqa: BLE001
            pass
        return json.dumps({
            "host": host, "port": port, "protocol": protocol, "cipher": cipher,
            "subject": subject, "issuer": issuer,
            "validFrom": parsed.not_valid_before_utc.isoformat(),
            "validTo": parsed.not_valid_after_utc.isoformat(),
            "daysRemaining": (parsed.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days,
            "subjectAlternativeNames": san,
            "serialNumber": str(parsed.serial_number),
        }, indent=2, ensure_ascii=False)
    except ImportError:
        return json.dumps({"host": host, "port": port, "protocol": protocol, "cipher": cipher,
                           "note": "Detalhes do certificado exigem 'cryptography' (pip install cryptography); conexao TLS confirmada."})


def decode_jwt_token(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return json.dumps({"error": "Token JWT deve ter 3 partes separadas por '.'"})

    def _b64(seg: str) -> dict:
        padded = seg + "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

    try:
        header, payload = _b64(parts[0]), _b64(parts[1])
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"JWT invalido: {exc}"})
    import datetime

    exp = payload.get("exp")
    out: dict[str, Any] = {"header": header, "payload": payload, "signature": parts[2], "algorithm": header.get("alg")}
    if isinstance(exp, (int, float)):
        out["expiresAt"] = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc).isoformat()
        out["expired"] = exp < time.time()
    return json.dumps(out, indent=2, ensure_ascii=False)


def trace_redirects(url: str, max_redirects: int = 10, user_agent: str | None = None) -> str:
    import http.client
    from urllib.parse import urljoin, urlparse

    chain: list[dict[str, Any]] = []
    current = url
    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parsed.netloc, timeout=10)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            conn.request("GET", path, headers={"User-Agent": ua})
            resp = conn.getresponse()
            body = resp.read(1024)
            chain.append({"url": current, "status": resp.status, "location": resp.getheader("Location"),
                          "cookies": resp.getheader("Set-Cookie"), "bodyPreview": body[:200].decode(errors="replace")})
            if resp.status in (301, 302, 303, 307, 308) and resp.getheader("Location"):
                current = urljoin(current, resp.getheader("Location"))
                continue
            break
        finally:
            conn.close()
    return json.dumps({"chain": chain, "finalUrl": current}, indent=2, ensure_ascii=False)


def parse_openapi_spec(spec_url: str) -> str:
    try:
        with urllib.request.urlopen(spec_url, timeout=20) as resp:
            text = resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)})
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            spec = yaml.safe_load(text)
        except ImportError:
            return json.dumps({"error": "Spec YAML exige PyYAML (pip install pyyaml)", "rawPreview": text[:2000]})
    endpoints = []
    for path, methods in (spec.get("paths") or {}).items():
        for method, op in (methods or {}).items():
            if not isinstance(op, dict):
                continue
            endpoints.append({
                "path": path, "method": method.upper(),
                "parameters": [{"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False),
                                "type": (p.get("schema") or {}).get("type", "any")} for p in op.get("parameters", [])],
                "summary": op.get("summary", ""),
            })
    return json.dumps({"title": (spec.get("info") or {}).get("title"), "version": (spec.get("info") or {}).get("version"),
                       "endpoints": endpoints, "schemas": list((spec.get("components") or {}).get("schemas", {}).keys())}, indent=2, ensure_ascii=False)


def export_har_log(network_entries: list[dict]) -> str:
    entries = []
    for e in network_entries:
        data = e.get("data") or {}
        req = (data.get("request") or {}) if isinstance(data, dict) else {}
        resp = (data.get("response") or {}) if isinstance(data, dict) else {}
        entries.append({
            "startedDateTime": data.get("timestamp", ""),
            "request": {"method": req.get("method", ""), "url": req.get("url", ""),
                        "headers": [{"name": k, "value": str(v)} for k, v in (req.get("headers") or {}).items()]},
            "response": {"status": resp.get("status", 0), "statusText": resp.get("statusText", ""),
                         "headers": [{"name": k, "value": str(v)} for k, v in (resp.get("headers") or {}).items()]},
            "type": e.get("type"),
        })
    har = {"log": {"version": "1.2", "creator": {"name": "AnonSite MCP", "version": "1.0"}, "entries": entries}}
    return json.dumps(har, indent=2, ensure_ascii=False)
