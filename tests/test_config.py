import json
import random

from anonsite import config as cfg


def test_resolve_search_with_space():
    s = cfg.Settings(search_engine="DuckDuckGo")
    assert cfg.resolve_input_to_url(s, "como fazer bolo") == "https://duckduckgo.com/?q=como+fazer+bolo"


def test_resolve_search_without_dot():
    s = cfg.Settings()
    assert cfg.resolve_input_to_url(s, "localhost") == "https://duckduckgo.com/?q=localhost"


def test_resolve_adds_https():
    s = cfg.Settings()
    assert cfg.resolve_input_to_url(s, "example.com") == "https://example.com"


def test_resolve_keeps_scheme():
    s = cfg.Settings()
    assert cfg.resolve_input_to_url(s, "http://example.com/x") == "http://example.com/x"


def test_google_search():
    s = cfg.Settings(search_engine="Google")
    assert cfg.resolve_input_to_url(s, "teste") == "https://www.google.com/search?q=teste&gbv=1"


def test_settings_roundtrip(tmp_path):
    p = tmp_path / "config.json"
    s = cfg.Settings(doh="https://dns.google/dns-query", proxy="socks5://127.0.0.1:1080", ghost_tab=True, mcp_enabled=True, memory_optimization=2)
    cfg.save_settings(s, p)
    assert cfg.load_settings(p) == s


def test_chromium_flags_include_doh_and_proxy():
    s = cfg.Settings(doh="https://dns.google/dns-query", proxy="socks5://127.0.0.1:1080")
    flags = " ".join(cfg.chromium_flags(s))
    assert "--dns-over-https-mode=secure" in flags
    assert "dns.google/dns-query" in flags
    assert "--proxy-server=socks5://127.0.0.1:1080" in flags
    assert "--remote-debugging-port=9222" in flags


def test_chromium_flags_no_doh_by_default():
    flags = " ".join(cfg.chromium_flags(cfg.Settings()))
    assert "dns-over-https" not in flags
