import json
import random

from anonsite.fingerprint import PROFILES, anti_tracking_js, random_fingerprint
from anonsite.session import build_session_document, dump_session, find_tab_for_storage, injection_js_for_storage, parse_session


def test_five_profiles():
    assert len(PROFILES) == 5


def test_random_fingerprint_has_noise_in_range():
    fp = random_fingerprint(random.Random(1))
    assert 1 <= fp.canvas_noise <= 99
    assert fp.user_agent.startswith("Mozilla/5.0")


def test_anti_tracking_js_contains_spoofs():
    js = anti_tracking_js(PROFILES[0])
    assert "RTCPeerConnection" in js
    assert "ANGLE (NVIDIA" in js
    assert "__FP_NOISE" in js
    assert "deviceMemory" in js


def test_session_roundtrip():
    doc = build_session_document({"cookies": [{"name": "a"}]}, [{"url": "https://x.com/", "localStorage": {"k": "v"}}])
    cookies, storages = parse_session(dump_session(doc["cookies"], doc["storages"]))
    assert cookies["cookies"][0]["name"] == "a"
    assert storages[0]["localStorage"]["k"] == "v"


def test_session_parse_tolerates_bom():
    cookies, _ = parse_session("\ufeff" + dump_session({"cookies": []}, []))
    assert cookies == {"cookies": []}


def test_injection_scripts_cover_storage_and_cookie():
    scripts = injection_js_for_storage({"localStorage": {"a": "1"}, "sessionStorage": {"b": "2"}, "documentCookie": "x=1; y=2"})
    joined = " ".join(scripts)
    assert "localStorage.setItem" in joined
    assert "sessionStorage.setItem" in joined
    assert "document.cookie" in joined


def test_find_tab_by_domain():
    assert find_tab_for_storage(["https://a.com/", "https://b.com/p"], "https://b.com/outra") == 1
    assert find_tab_for_storage(["https://a.com/"], "https://desconhecido.com/") == 0
