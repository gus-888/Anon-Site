"""Configuração e persistência.

Original (C++): cada opção era um arquivo solto em %TEMP% — ``AnonDoH.txt``,
``AnonProxy.txt``, ``AnonSearch.txt``, ``AnonGhostTab.txt``,
``AnonMcpEnabled.txt`` — e o perfil do navegador era apagado a cada
inicialização (``%TEMP%\\AnonBrowserTempData``).

Port Python: um único JSON em ``~/.config/anonsite/config.json``
(``%APPDATA%\\anonsite\\config.json`` no Windows). A leitura tolera os
arquivos legados ``Anon*.txt`` do %TEMP% na primeira execução e os migra,
para quem já usava o original não perder DoH/proxy/buscador.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_NAME = "anonsite"
API_HOST = "127.0.0.1"
API_PORT = 8383
CDP_PORT = 9222  # remote-debugging do QtWebEngine/Chromium (só localhost)
DEFAULT_SEARCH_ENGINE = "DuckDuckGo"

DOH_PRESETS: dict[str, str] = {
    "Nenhum (Inseguro - Operadora)": "none",
    "Cloudflare (1.1.1.1)": "https://chrome.cloudflare-dns.com/dns-query",
    "Quad9 (Privacidade e Anti-Malware)": "https://dns.quad9.net/dns-query",
    "AdGuard (Adblock Nativo)": "https://dns.adguard-dns.com/dns-query",
    "Google (8.8.8.8)": "https://dns.google/dns-query",
}
DOH_URL_TO_LABEL = {v: k for k, v in DOH_PRESETS.items()}

SEARCH_ENGINES: dict[str, str] = {
    "DuckDuckGo": "https://duckduckgo.com/",
    "Google": "https://www.google.com/",
}
SEARCH_QUERY_URL: dict[str, str] = {
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "Google": "https://www.google.com/search?q={q}&gbv=1",
}


def config_dir() -> Path:
    """Diretório de configuração por plataforma (XDG no Linux, APPDATA no Win)."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_NAME


def profile_dir() -> Path:
    """Perfil efêmero do QtWebEngine — apagado a cada inicialização (como o original)."""
    return Path(tempfile.gettempdir()) / "AnonBrowserTempData"


def ghost_profile_dir() -> Path:
    return Path(tempfile.gettempdir()) / f"GhostTab_{os.getpid()}"


def screenshot_path() -> Path:
    import time

    return Path(tempfile.gettempdir()) / f"AnonScreenshot_{int(time.time() * 1000)}.png"


@dataclass
class Settings:
    doh: str = "none"  # URL do template DoH ou "none"
    proxy: str = ""  # ex.: socks5://127.0.0.1:1080
    search_engine: str = DEFAULT_SEARCH_ENGINE
    ghost_tab: bool = False
    mcp_enabled: bool = True  # MCP/API ligados por padrão; --no-mcp desliga
    memory_optimization: int = 1  # 0=Desligado, 1=Balanceado, 2=Agressivo

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {f for f in asdict(cls())}
        clean = {k: v for k, v in (data or {}).items() if k in known}
        obj = cls(**clean)
        obj.memory_optimization = max(0, min(2, int(obj.memory_optimization)))
        return obj


def _read_legacy_temp_file(name: str) -> str | None:
    try:
        text = (Path(tempfile.gettempdir()) / name).read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    return text or None


def load_settings(path: Path | None = None) -> Settings:
    """Carrega o JSON; se não existir, tenta migrar os Anon*.txt legados."""
    path = path or (config_dir() / "config.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Settings.from_dict(data)
    except (OSError, json.JSONDecodeError):
        pass
    # Migração legada (uma única vez, na primeira execução)
    s = Settings()
    if (v := _read_legacy_temp_file("AnonDoH.txt")) is not None:
        s.doh = v
    if (v := _read_legacy_temp_file("AnonProxy.txt")) is not None:
        s.proxy = v
    if (v := _read_legacy_temp_file("AnonSearch.txt")) is not None:
        s.search_engine = v if v in SEARCH_ENGINES else DEFAULT_SEARCH_ENGINE
    if (v := _read_legacy_temp_file("AnonGhostTab.txt")) is not None:
        s.ghost_tab = v.strip() == "1"
    if (v := _read_legacy_temp_file("AnonMcpEnabled.txt")) is not None:
        s.mcp_enabled = v.strip() == "1"
    return s


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    path = path or (config_dir() / "config.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(settings.to_json(), encoding="utf-8")
    return path


def home_url(settings: Settings) -> str:
    return SEARCH_ENGINES.get(settings.search_engine, SEARCH_ENGINES[DEFAULT_SEARCH_ENGINE])


def search_url(settings: Settings, query: str) -> str:
    from urllib.parse import quote_plus

    template = SEARCH_QUERY_URL.get(settings.search_engine, SEARCH_QUERY_URL[DEFAULT_SEARCH_ENGINE])
    return template.format(q=quote_plus(query))


def resolve_input_to_url(settings: Settings, raw: str) -> str:
    """Mesma regra do original: com espaço ou sem ponto -> busca; sem esquema -> https://."""
    text = raw.strip()
    if not text:
        return home_url(settings)
    if " " in text or "." not in text:
        return search_url(settings, text)
    if not text.startswith(("http://", "https://")):
        return "https://" + text
    return text


def chromium_flags(settings: Settings) -> list[str]:
    """Flags passadas ao Chromium do QtWebEngine via QTWEBENGINE_CHROMIUM_FLAGS.

    Original (C++): ``--enable-features=ParallelDownloading`` (+ DoH, proxy,
    e na variante .bak: anti-automação, WebRTC restrito, cache mínimo).
    """
    features = ["ParallelDownloading"]
    flags = [f"--remote-debugging-port={CDP_PORT}"]
    if settings.doh and settings.doh != "none":
        features += ["EncryptedClientHello", "DnsOverHttps"]
        flags += ["--dns-over-https-mode=secure", f"--dns-over-https-templates={settings.doh}"]
    if settings.proxy:
        flags.append(f"--proxy-server={settings.proxy}")
    flags += [
        "--disable-blink-features=AutomationControlled",
        "--force-webrtc-ip-handling-policy=default_public_interface_only",
        "--enforce-webrtc-ip-permission-check",
        "--disk-cache-size=1",
        "--media-cache-size=1",
        "--process-per-site",
        "--disable-gpu-program-cache",
        "--disable-gpu-shader-disk-cache",
        "--disable-logging",
        "--disable-breakpad",
    ]
    return [f"--enable-features={','.join(features)}"] + flags
