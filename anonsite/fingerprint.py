"""Fingerprint: os 5 perfis do original + o JS anti-tracking.

No C++ havia duas variantes: o ``.bak`` aplicava UA/timezone/anti-tracking/
negação de permissões/spoof de cabeçalhos; o ``.cpp`` atual os deixava
comentados ("pure native Edge behavior") mas mantinha o botão
"Limpar Fingerprint (x-finger)". Aqui a proteção vem LIGADA por padrão
— é o comportamento que o nome AnonSite promete — e pode ser desligada
aba por aba pelo painel Central se um site quebrar.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class Fingerprint:
    user_agent: str
    platform: str  # valor de Sec-CH-UA-Platform, ex.: '"Windows"'
    ch_ua: str
    tz_id: str
    webgl_vendor: str
    webgl_renderer: str
    canvas_noise: int


PROFILES: list[Fingerprint] = [
    Fingerprint(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        '"Windows"',
        '"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="8"',
        "Europe/London",
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        0,
    ),
    Fingerprint(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        '"Linux"',
        '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        "America/New_York",
        "Google Inc. (AMD)",
        "ANGLE (AMD, AMD Radeon RX 6700 XT, OpenGL 4.6)",
        0,
    ),
    Fingerprint(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        '"macOS"',
        '"Google Chrome";v="121", "Chromium";v="121", "Not?A_Brand";v="99"',
        "Asia/Tokyo",
        "Google Inc. (Apple)",
        "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)",
        0,
    ),
    Fingerprint(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        '"Windows"',
        '"Google Chrome";v="122", "Chromium";v="122", "Not?A_Brand";v="5"',
        "Australia/Sydney",
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        0,
    ),
    Fingerprint(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        '"Linux"',
        '"Firefox";v="115", "Not?A_Brand";v="14"',
        "Europe/Berlin",
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti, OpenGL 4.6)",
        0,
    ),
]


def random_fingerprint(rng: random.Random | None = None) -> Fingerprint:
    rng = rng or random.SystemRandom()
    fp = PROFILES[rng.randrange(len(PROFILES))]
    return Fingerprint(
        user_agent=fp.user_agent,
        platform=fp.platform,
        ch_ua=fp.ch_ua,
        tz_id=fp.tz_id,
        webgl_vendor=fp.webgl_vendor,
        webgl_renderer=fp.webgl_renderer,
        canvas_noise=rng.randint(1, 99),
    )


def shuffle_canvas_noise(fp: Fingerprint, rng: random.Random | None = None) -> Fingerprint:
    rng = rng or random.SystemRandom()
    fp.canvas_noise = rng.randint(1, 99)
    return fp


def _js_str(value: str) -> str:
    """Escapa uma string para dentro de aspas simples em JS."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def anti_tracking_js(fp: Fingerprint) -> str:
    """Tradução fiel de GetAntiTrackingJS() do C++."""
    return f"""(function() {{
  delete window.RTCPeerConnection; delete window.mozRTCPeerConnection; delete window.webkitRTCPeerConnection;
  Object.defineProperty(navigator, 'webdriver', {{get: () => undefined}});
  if (!window.chrome) {{ window.chrome = {{}}; }}
  if (!window.chrome.runtime) {{ window.chrome.runtime = {{}}; }}
  if (!window.__FP_INJECTED__) {{
    window.__FP_INJECTED__ = true;
    const _origGetParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(p) {{ if(p===37445) return window.__FP_VENDOR; if(p===37446) return window.__FP_RENDERER; return _origGetParam.call(this, p); }};
    if (typeof WebGL2RenderingContext !== 'undefined') {{
      const _origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function(p) {{ if(p===37445) return window.__FP_VENDOR; if(p===37446) return window.__FP_RENDERER; return _origGetParam2.call(this, p); }};
    }}
    const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x,y,w,h) {{ let d = _origGetImageData.call(this,x,y,w,h); d.data[0]=(d.data[0]+window.__FP_NOISE)%256; return d; }};
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(t,q) {{ return _origToDataURL.call(this,t,q).replace('A', window.__FP_NOISE.toString()); }};
    Object.defineProperty(navigator, 'deviceMemory', {{get: () => 8}});
    Object.defineProperty(navigator, 'hardwareConcurrency', {{get: () => 4}});
    Object.defineProperty(navigator, 'languages', {{get: () => ['en-US', 'en']}});
    Object.defineProperty(navigator, 'plugins', {{get: () => [1, 2, 3, 4, 5]}});
  }}
  window.__FP_VENDOR = '{_js_str(fp.webgl_vendor)}';
  window.__FP_RENDERER = '{_js_str(fp.webgl_renderer)}';
  window.__FP_NOISE = {fp.canvas_noise};
}})();
"""


CLEAR_FINGERPRINT_JS = """(function() {
  try {
    localStorage.removeItem('x-finger');
    sessionStorage.removeItem('x-finger');
    const purge = (s) => {
      const removeKeys = [];
      for (let i = 0; i < s.length; i++) {
        const k = s.key(i);
        if (k && /finger|visitor|fpjs|_fp|device_id|deviceId/i.test(k)) {
          removeKeys.push(k);
        }
      }
      removeKeys.forEach(k => s.removeItem(k));
    };
    purge(localStorage);
    purge(sessionStorage);
  } catch(e) {}
})();
"""

CLEAR_ALL_STORAGE_JS = "localStorage.clear(); sessionStorage.clear();"
