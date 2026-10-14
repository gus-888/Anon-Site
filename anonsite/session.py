"""Exportação / importação de sessão — formato idêntico ao do C++.

Formato (``AnonSession.json``):
    {
      "cookies": {"cookies": [...]},   # Network.getAllCookies
      "storages": [
        {"url": ..., "localStorage": {...}, "sessionStorage": {...},
         "documentCookie": "..."}
      ]
    }

A coleta em si vive no browser (JS via Qt/CDP); aqui ficam a
serialização, o parsing tolerante e os scripts JS de coleta/injeção,
testáveis sem GUI.
"""
from __future__ import annotations

import json
from typing import Any

COLLECT_LOCAL_STORAGE_JS = (
    "(function(){ try { let o={}; for(let k=0;k<localStorage.length;k++)"
    "{let key=localStorage.key(k); o[key]=localStorage.getItem(key);} "
    "return JSON.stringify(o); } catch(e){ return '{}'; } })()"
)
COLLECT_SESSION_STORAGE_JS = (
    "(function(){ try { let o={}; for(let k=0;k<sessionStorage.length;k++)"
    "{let key=sessionStorage.key(k); o[key]=sessionStorage.getItem(key);} "
    "return JSON.stringify(o); } catch(e){ return '{}'; } })()"
)
COLLECT_DOCUMENT_COOKIE_JS = (
    "(function(){ try { return document.cookie || ''; } catch(e){ return ''; } })()"
)


def build_session_document(cookies: dict, storages: list[dict]) -> dict:
    return {"cookies": cookies, "storages": storages}


def dump_session(cookies: dict, storages: list[dict]) -> str:
    return json.dumps(build_session_document(cookies, storages), ensure_ascii=False, indent=2)


def parse_session(text: str) -> tuple[dict, list[dict]]:
    """Devolve (cookies_obj, storages). Tolera JSON com BOM e campos ausentes."""
    if text.startswith("\ufeff"):
        text = text[1:]
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Sessão inválida: raiz não é um objeto JSON")
    cookies = data.get("cookies") or {}
    storages = data.get("storages") or []
    if not isinstance(cookies, dict) or not isinstance(storages, list):
        raise ValueError("Sessão inválida: 'cookies' ou 'storages' com tipo errado")
    return cookies, storages


def injection_js_for_storage(storage: dict) -> list[str]:
    """Scripts JS que restauram local/sessionStorage + document.cookie de uma aba."""
    scripts: list[str] = []
    local = storage.get("localStorage") or {}
    session = storage.get("sessionStorage") or {}
    doc_cookie = storage.get("documentCookie") or ""
    if local:
        scripts.append(
            "(function(){ try { let d="
            + json.dumps(local, ensure_ascii=False)
            + "; for(let k in d) { localStorage.setItem(k, d[k]); } } catch(e){} })()"
        )
    if session:
        scripts.append(
            "(function(){ try { let d="
            + json.dumps(session, ensure_ascii=False)
            + "; for(let k in d) { sessionStorage.setItem(k, d[k]); } } catch(e){} })()"
        )
    if doc_cookie:
        escaped = json.dumps(doc_cookie, ensure_ascii=False)
        scripts.append(
            "(function(){ try { let parts="
            + escaped
            + ".split('; '); parts.forEach(function(p){ document.cookie=p+'; path=/'; }); "
            "} catch(e){} })()"
        )
    return scripts


def domain_of(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc or url


def find_tab_for_storage(tab_urls: list[str], storage_url: str) -> int:
    """Aba cujo domínio bate com o da sessão (mesma regra do C++), ou 0."""
    wanted = domain_of(storage_url)
    for i, tab_url in enumerate(tab_urls):
        if domain_of(tab_url) == wanted:
            return i
    return 0
