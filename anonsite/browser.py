"""Interface do navegador — PyQt6 + QtWebEngine.

Mapeamento do original (Win32 + WebView2) para Qt:

- Janela Win32 sem moldura + DWM dark  -> QMainWindow com moldura nativa
  (a moldura customizada do original só existia no Windows; a nativa
  funciona igual nos dois SOs e respeita o tema do sistema).
- TabCtrl Win32                    -> QTabWidget (movable, closable,
  menu de contexto, fechar com clique do meio, reordenar arrastando).
- WebView2                         -> QWebEngineView (Chromium).
- WebResourceRequested (spoof de cabeçalhos) -> QWebEngineUrlRequestInterceptor.
- PermissionRequested (negar tudo) -> featurePermissionRequested -> Denied.
- AddScriptToExecuteOnDocumentCreated -> QWebEngineScript (DocumentCreation).
- CallDevToolsProtocolMethod       -> CDP via remote-debugging (cdp.py).
- DownloadStarting                 -> QWebEngineProfile.downloadRequested.
- WM_MCP_API / SendMessage          -> Bridge (fila + QTimer, ver abaixo).
- GetTempPath Anon*.txt            -> config.py (JSON único).
"""
from __future__ import annotations

import os
import shutil
import threading
import time
import traceback
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, Callable

from . import config as cfg
from .cdp import CdpClient, list_targets
from .fingerprint import (
    CLEAR_ALL_STORAGE_JS,
    CLEAR_FINGERPRINT_JS,
    Fingerprint,
    anti_tracking_js,
    random_fingerprint,
    shuffle_canvas_noise,
)
from .network_log import NetworkLog
from .session import (
    COLLECT_DOCUMENT_COOKIE_JS,
    COLLECT_LOCAL_STORAGE_JS,
    COLLECT_SESSION_STORAGE_JS,
    dump_session,
    find_tab_for_storage,
    injection_js_for_storage,
    parse_session,
)

NETWORK_LOG = NetworkLog()


# ---------------------------------------------------------------------------
# Bridge: a API HTTP (thread) pede ações à thread do Qt sem travar a UI.
# Espelha o SendMessageW(g_hWndMain, MSG_MCP_API, ...) do C++.
# ---------------------------------------------------------------------------
@dataclass
class BridgeRequest:
    op: str
    payload: dict = field(default_factory=dict)
    done: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    success: bool = False


class Bridge:
    def __init__(self) -> None:
        self.queue: Queue[BridgeRequest] = Queue()
        self.pending_js: dict[int, BridgeRequest] = {}

    def submit(self, op: str, payload: dict | None = None, timeout: float = 15.0) -> tuple[bool, Any]:
        req = BridgeRequest(op=op, payload=payload or {})
        self.queue.put(req)
        if not req.done.wait(timeout):
            return False, "timeout aguardando a thread da interface"
        return req.success, req.result


BRIDGE = Bridge()


# ---------------------------------------------------------------------------
# Página de erro OFFLINE — tradução do errorHtml do C++.
# ---------------------------------------------------------------------------
def offline_html(error_name: str = "Problema Desconhecido", code: str = "") -> str:
    return f"""<html><body style='background:#0a0a0a;color:#ff3333;font-family:"Segoe UI", sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>
<div style='text-align:center;border:1px solid #ff3333;padding:40px;box-shadow:0 0 20px #ff3333;border-radius:10px;'>
<h1 style='font-size:80px;margin:0;text-shadow:0 0 10px #ff3333;'>OFFLINE</h1>
<h2 style='text-transform:uppercase;letter-spacing:4px;'>AnonSite Network Failure</h2>
<h3 style='color:#ff8888;margin-bottom:20px;'>Código de Erro: {code} ({error_name})</h3>
<p style='color:#ccc;max-width:550px;line-height:1.6;font-size:16px;'>A rede falhou ou o domínio não pôde ser resolvido na internet.<br><br>
<b style='color:#fff;'>Como resolver:</b><br>
- Você tem conexão ativa com a internet?<br>
- Confira se a porta/IP do <b style='color:#ffaaaa;'>Proxy</b> na central de engrenagem estão corretos.<br>
- Tente mudar a opção de <b style='color:#ffaaaa;'>DNS Criptografado</b> (Ex: Cloudflare/Quad9).<br>
- O provedor de rede pode estar rastreando e bloqueando este tráfego.</p></div></body></html>"""


DOWNLOADS_HTML = """<html><body style='background:#1e1e1e;color:#ddd;font-family:"Segoe UI",sans-serif;padding:24px;'>
<h1>⬇ Gerenciador de Downloads</h1><p>Os downloads aparecem na janela de Downloads (botão ⬇ na barra).
O histórico de downloads é apagado junto com a sessão, como no original.</p></body></html>"""


from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest
from PyQt6.QtWebEngineCore import (
    QWebEngineDownloadRequest,
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
    QWebEngineUrlRequestInterceptor,
    QWebEngineUrlRequestInfo,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSlider,
    QSplitter,
    QTabBar,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QLineEdit,
)


# ---------------------------------------------------------------------------
# Interceptor de requisições — spoof de cabeçalhos (variante .bak do C++).
# O .cpp atual tinha isso comentado; aqui fica ativo por padrão.
# ---------------------------------------------------------------------------
class RequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, get_fp: Callable[[], Fingerprint]) -> None:
        super().__init__()
        self._get_fp = get_fp

    def interceptRequest(self, info: QWebEngineUrlRequestInfo) -> None:  # noqa: N802
        fp = self._get_fp()
        # Referer original é mantido (o C++ comentava isso p/ Cloudflare Turnstile).
        info.setHttpHeader(b"Sec-CH-UA", fp.ch_ua.encode())
        info.setHttpHeader(b"Sec-CH-UA-Mobile", b"?0")
        info.setHttpHeader(b"Sec-CH-UA-Platform", fp.platform.encode())
        info.setHttpHeader(b"Accept-Language", b"en-US,en;q=0.9")
        info.setHttpHeader(b"DNT", b"1")


class TabBar(QTabBar):
    middle_click_close = None  # ligado no __init__ via sinal dinâmico

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        from PyQt6.QtCore import pyqtSignal

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.MouseButton.MiddleButton:
            idx = self.tabAt(event.pos())
            if idx >= 0:
                parent = self.parent()
                if hasattr(parent, "close_tab"):
                    parent.close_tab(idx)
                return
        super().mousePressEvent(event)


class DownloadsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Gerenciador de Downloads")
        self.resize(520, 300)
        layout = QVBoxLayout(self)
        self.list = QListWidget()
        layout.addWidget(self.list)
        self._items: dict[int, QListWidgetItem] = {}
        self._downloads: dict[int, Any] = {}

    def add_download(self, download) -> None:
        item = QListWidgetItem(f"{download.suggestedFileName()} — 0%")
        self.list.addItem(item)
        key = id(download)
        self._items[key] = item
        self._downloads[key] = download
        download.receivedBytesChanged.connect(lambda: self._update(download))
        download.stateChanged.connect(lambda _s: self._update(download))

    def _update(self, download) -> None:
        item = self._items.get(id(download))
        if not item:
            return
        total = download.totalBytes()
        received = download.receivedBytes()
        pct = int(received * 100 / total) if total > 0 else 0
        state = download.state()
        state_name = {
            QWebEngineDownloadRequest.DownloadState.DownloadRequested: "solicitado",
            QWebEngineDownloadRequest.DownloadState.DownloadInProgress: "baixando",
            QWebEngineDownloadRequest.DownloadState.DownloadCompleted: "concluído",
            QWebEngineDownloadRequest.DownloadState.DownloadCancelled: "cancelado",
            QWebEngineDownloadRequest.DownloadState.DownloadInterrupted: "interrompido",
        }.get(state, str(state))
        item.setText(f"{download.suggestedFileName()} — {pct}% — {state_name}")


class MainWindow(QMainWindow):
    def __init__(self, settings: cfg.Settings, fingerprint: Fingerprint, headless: bool = False) -> None:
        super().__init__()
        self.settings = settings
        self.fp = fingerprint
        self.headless = headless  # sem janela: o app não fecha ao fechar a última aba
        self.tabs: list[dict[str, Any]] = []  # {view, profile, pinned, muted, ghost}
        self._split_active = False
        self._split_left = -1
        self._split_right = -1
        self._splitter: QSplitter | None = None
        self._net = QNetworkAccessManager(self)

        self.setWindowTitle("AnonSite — best anon browser")
        self.resize(1024, 768)

        # ---- perfil padrão (efêmero) ----
        prof = QWebEngineProfile.defaultProfile()
        prof.setPersistentStoragePath(str(cfg.profile_dir()))
        prof.setCachePath(str(cfg.profile_dir() / "cache"))
        prof.setHttpUserAgent(self.fp.user_agent)
        self._apply_memory_profile(prof)
        prof.downloadRequested.connect(self._on_download_requested)
        self._interceptor = RequestInterceptor(lambda: self.fp)
        prof.setUrlRequestInterceptor(self._interceptor)

        # ---- barra de ferramentas ----
        toolbar = QToolBar("Navegação")
        self.addToolBar(toolbar)
        self._act_back = QAction("◀", self)
        self._act_back.triggered.connect(lambda: self._current_view().back() if self._current_view() else None)
        self._act_fwd = QAction("▶", self)
        self._act_fwd.triggered.connect(lambda: self._current_view().forward() if self._current_view() else None)
        self._act_reload = QAction("⟳", self)
        self._act_reload.triggered.connect(lambda: self._current_view().reload() if self._current_view() else None)
        self._act_home = QAction("⌂", self)
        self._act_home.triggered.connect(self._go_home)
        for act in (self._act_back, self._act_fwd, self._act_reload, self._act_home):
            toolbar.addAction(act)
        self.address = QLineEdit()
        self.address.setPlaceholderText("Pesquisar ou digitar endereço")
        self.address.returnPressed.connect(self._on_address_enter)
        toolbar.addWidget(self.address)
        self._act_new_tab = QAction("+", self)
        self._act_new_tab.triggered.connect(lambda: self.new_tab(cfg.home_url(self.settings)))
        toolbar.addAction(self._act_new_tab)
        self.downloads_dialog = DownloadsDialog(self)
        self._act_downloads = QAction("⬇", self)
        self._act_downloads.triggered.connect(self._open_downloads)
        toolbar.addAction(self._act_downloads)
        self._act_settings = QAction("⚙", self)
        self._act_settings.triggered.connect(self._open_settings)
        toolbar.addAction(self._act_settings)

        # ---- abas ----
        from PyQt6.QtWidgets import QStackedWidget

        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabBar(TabBar(self.tab_widget))
        self.tab_widget.setMovable(True)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self._on_current_changed)
        self.tab_widget.tabBar().tabMoved.connect(self._on_tab_moved)
        self.tab_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tab_widget.customContextMenuRequested.connect(self._tab_context_menu)
        self._stack.addWidget(self.tab_widget)

        # ---- atalhos ----
        from PyQt6.QtGui import QShortcut, QKeySequence

        QShortcut(QKeySequence("Ctrl+T"), self, activated=lambda: self.new_tab(cfg.home_url(self.settings)))
        QShortcut(QKeySequence("Ctrl+W"), self, activated=lambda: self.close_tab(self.tab_widget.currentIndex()))
        QShortcut(QKeySequence("Ctrl+R"), self, activated=lambda: self._current_view().reload() if self._current_view() else None)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=lambda: (self.address.setFocus(), self.address.selectAll()))

        # ---- bridge API 8383 ----
        self._bridge_timer = QTimer(self)
        self._bridge_timer.timeout.connect(self._poll_bridge)
        self._bridge_timer.start(50)

    # ---------------- helpers ----------------
    def _apply_memory_profile(self, profile) -> None:
        level = self.settings.memory_optimization
        cache_type = {
            0: QWebEngineProfile.HttpCacheType.DiskHttpCache,
            1: QWebEngineProfile.HttpCacheType.MemoryHttpCache,
            2: QWebEngineProfile.HttpCacheType.NoCache,
        }[level]
        profile.setHttpCacheType(cache_type)
        profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies
            if level == 2
            else QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
        )

    def _current_view(self):
        idx = self.tab_widget.currentIndex()
        if 0 <= idx < len(self.tabs):
            return self.tabs[idx]["view"]
        return None

    def _current_index(self) -> int:
        return self.tab_widget.currentIndex()

    def _js_blocking(self, view, script: str, timeout_ms: int = 5000):
        """runJavaScript síncrono via loop local (espelha ExecuteScriptSync do C++)."""
        from PyQt6.QtCore import QEventLoop, QTimer as _T

        loop = QEventLoop()
        holder: list = []
        view.page().runJavaScript(script, lambda r: (holder.append(r), loop.quit()))
        _T.singleShot(timeout_ms, loop.quit)
        loop.exec()
        return holder[0] if holder else None

    def _cdp_ws_for_tab(self, index: int) -> str | None:
        if not (0 <= index < len(self.tabs)):
            return None
        tab_url = self.tabs[index]["view"].url().toString()
        best = None
        for target in list_targets():
            if target.get("type") != "page" or not target.get("webSocketDebuggerUrl"):
                continue
            if target.get("url") == tab_url:
                return target["webSocketDebuggerUrl"]
            if not best and target.get("url"):
                best = target["webSocketDebuggerUrl"]
        return best

    # ---------------- abas ----------------
    def new_tab(self, url: str, ghost: bool | None = None) -> int:
        use_ghost = self.settings.ghost_tab if ghost is None else ghost
        if use_ghost:
            profile = QWebEngineProfile()
            profile.setPersistentStoragePath(str(cfg.ghost_profile_dir() / f"tab{len(self.tabs)}_{int(time.time())}"))
            profile.setHttpUserAgent(self.fp.user_agent)
            self._apply_memory_profile(profile)
            profile.downloadRequested.connect(self._on_download_requested)
            profile.setUrlRequestInterceptor(self._interceptor)
        else:
            profile = QWebEngineProfile.defaultProfile()
        view = QWebEngineView()
        page = QWebEnginePage(profile, view)
        view.setPage(page)
        self._install_page_handlers(view, page)
        self._inject_fingerprint(page)
        tab = {"view": view, "profile": profile, "pinned": False, "muted": False, "ghost": use_ghost}
        self.tabs.append(tab)
        idx = self.tab_widget.addTab(view, "Nova Guia")
        self.tab_widget.setCurrentIndex(idx)
        self._fetch_favicon(url)
        view.setUrl(QUrl(url))
        return idx

    def _install_page_handlers(self, view, page) -> None:
        page.featurePermissionRequested.connect(
            lambda url, feat: page.setFeaturePermission(
                url, feat, QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
            )
        )
        page.newWindowRequested.connect(
            lambda req: self.new_tab(req.requestedUrl().toString())
        )
        view.titleChanged.connect(lambda _t, v=view: self._update_tab_title(v))
        view.urlChanged.connect(lambda _u, v=view: self._on_url_changed(v))
        view.loadFinished.connect(lambda ok, v=view: self._on_load_finished(v, ok))
        view.iconChanged.connect(lambda _i, v=view: self._update_tab_title(v))

    def _inject_fingerprint(self, page) -> None:
        script = QWebEngineScript()
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(True)
        script.setSourceCode(anti_tracking_js(self.fp))
        page.scripts().insert(script)

    def _update_tab_title(self, view) -> None:
        for i, tab in enumerate(self.tabs):
            if tab["view"] is view:
                title = view.title() or "Nova Guia"
                if "Download" in title and "Edge" in title:
                    title = "Gerenciador de Downloads"
                if len(title) > 25:
                    title = title[:23] + "..."
                if tab["pinned"]:
                    title = "📌 " + title
                self.tab_widget.setTabText(i, title)
                break

    def _on_url_changed(self, view) -> None:
        if view is self._current_view() and not self.address.hasFocus():
            url = view.url().toString()
            if url == "edge://downloads":
                url = "//downloads"
            self.address.setText(url)
        for tab in self.tabs:
            if tab["view"] is view:
                self._fetch_favicon(view.url().toString())
                break

    def _on_load_finished(self, view, ok: bool) -> None:
        if not ok:
            # Qt não expõe o código do erro aqui; a página OFFLINE é a mesma do C++.
            view.setHtml(offline_html(), QUrl("about:blank"))

    def _on_current_changed(self, idx: int) -> None:
        if 0 <= idx < len(self.tabs):
            url = self.tabs[idx]["view"].url().toString()
            if url == "edge://downloads":
                url = "//downloads"
            self.address.setText(url)

    def _on_tab_moved(self, _from: int, _to: int) -> None:
        # Reordena self.tabs para espelhar a ordem visual (ReorderTab do C++).
        ordered = []
        for i in range(self.tab_widget.count()):
            w = self.tab_widget.widget(i)
            for tab in self.tabs:
                if tab["view"] is w:
                    ordered.append(tab)
                    break
        if len(ordered) == len(self.tabs):
            self.tabs = ordered

    def close_tab(self, index: int) -> None:
        if not (0 <= index < len(self.tabs)):
            return
        if self._split_active and index in (self._split_left, self._split_right):
            self.exit_split()
        tab = self.tabs.pop(index)
        self.tab_widget.removeTab(index)
        tab["view"].deleteLater()
        if not self.tabs:
            if self.headless:
                # Sem UI, fechar a última aba não pode matar o servidor MCP:
                # abre uma aba em branco e segue rodando.
                self.new_tab(cfg.home_url(self.settings))
                return
            QApplication.instance().quit()
            return
        if self.tab_widget.currentIndex() >= len(self.tabs):
            self.tab_widget.setCurrentIndex(len(self.tabs) - 1)

    def switch_to_tab(self, index: int) -> None:
        if self._split_active:
            self.exit_split()
        if 0 <= index < len(self.tabs):
            self.tab_widget.setCurrentIndex(index)

    # ---------------- split ----------------
    def enter_split(self, idx: int) -> None:
        if self._split_active:
            self.exit_split()
            return
        if not (0 <= idx < len(self.tabs)):
            return
        other = next((i for i in range(len(self.tabs)) if i != idx), -1)
        if other < 0:
            self.new_tab(cfg.home_url(self.settings))
            other = len(self.tabs) - 1
        self._split_left, self._split_right = idx, other
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        # Remove todas as abas (sem destruir as views) e coloca 2 no splitter.
        views = [t["view"] for t in self.tabs]
        while self.tab_widget.count():
            self.tab_widget.removeTab(0)
        self._splitter.addWidget(views[idx])
        self._splitter.addWidget(views[other])
        self._splitter.setSizes([500, 500])
        self._stack.addWidget(self._splitter)
        self._stack.setCurrentWidget(self._splitter)
        self._split_active = True

    def exit_split(self) -> None:
        if not self._split_active or self._splitter is None:
            return
        while self._splitter.count():
            w = self._splitter.widget(0)
            w.setParent(None)
        self._stack.removeWidget(self._splitter)
        self._splitter.deleteLater()
        self._splitter = None
        self._split_active = False
        for tab in self.tabs:
            self.tab_widget.addTab(tab["view"], tab["view"].title() or "Nova Guia")
        self.tab_widget.setCurrentIndex(min(self._split_left, len(self.tabs) - 1))
        self._stack.setCurrentWidget(self.tab_widget)
        self._split_left = self._split_right = -1

    # ---------------- navegação ----------------
    def _go_home(self) -> None:
        view = self._current_view()
        if view is not None:
            view.setUrl(QUrl("https://www.google.com"))  # fiel ao C++ (botão Home -> google.com)

    def _on_address_enter(self) -> None:
        url = cfg.resolve_input_to_url(self.settings, self.address.text())
        view = self._current_view()
        if view is not None:
            view.setUrl(QUrl(url))
        else:
            self.new_tab(url)

    def _open_downloads(self) -> None:
        self.downloads_dialog.show()
        self.downloads_dialog.raise_()

    # ---------------- favicon ----------------
    def _fetch_favicon(self, url: str) -> None:
        from urllib.parse import urlparse

        domain = urlparse(url).netloc
        if not domain:
            return
        req = QNetworkRequest(QUrl(f"https://www.google.com/s2/favicons?sz=32&domain={domain}"))
        reply = self._net.get(req)

        def _done(domain=domain, reply=reply):
            try:
                data = bytes(reply.readAll())
            finally:
                reply.deleteLater()
            if not data:
                return
            pix = QPixmap()
            if not pix.loadFromData(data):
                return
            for i, tab in enumerate(self.tabs):
                if urlparse(tab["view"].url().toString()).netloc == domain:
                    self.tab_widget.setTabIcon(i, QIcon(pix))

        reply.finished.connect(_done)

    # ---------------- downloads ----------------
    def _on_download_requested(self, download) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Salvar download", download.suggestedFileName()
        )
        if not path:
            download.cancel()
            return
        from pathlib import Path as _P

        p = _P(path)
        download.setDownloadDirectory(str(p.parent))
        download.setDownloadFileName(p.name)
        download.accept()
        self.downloads_dialog.add_download(download)
        self._open_downloads()

    # ---------------- menu de contexto da aba ----------------
    def _tab_context_menu(self, pos) -> None:
        idx = self.tab_widget.tabBar().tabAt(pos)
        if idx < 0:
            return
        tab = self.tabs[idx]
        menu = QMenu(self)
        mute = menu.addAction("Ativar Som" if tab["muted"] else "Desativar Som")
        dup = menu.addAction("Duplicar aba")
        pin = menu.addAction("Desafixar" if tab["pinned"] else "Fixar")
        menu.addSeparator()
        close = menu.addAction("Fechar aba")
        close_others = menu.addAction("Fechar outras abas")
        close_right = menu.addAction("Fechar abas à direita")
        close_left = menu.addAction("Fechar abas à esquerda")
        split = menu.addAction("Tela dividida (split)")
        chosen = menu.exec(self.tab_widget.mapToGlobal(pos))
        if chosen is mute:
            tab["muted"] = not tab["muted"]
            js = (
                "document.querySelectorAll('video,audio').forEach(e=>{e.muted=true;e.volume=0});"
                if tab["muted"]
                else "document.querySelectorAll('video,audio').forEach(e=>{e.muted=false;e.volume=1});"
            )
            tab["view"].page().runJavaScript(js)
        elif chosen is dup:
            self.new_tab(tab["view"].url().toString())
        elif chosen is pin:
            tab["pinned"] = not tab["pinned"]
            self._update_tab_title(tab["view"])
        elif chosen is close:
            self.close_tab(idx)
        elif chosen is close_others:
            for i in range(len(self.tabs) - 1, -1, -1):
                if i != idx and not self.tabs[i]["pinned"]:
                    self.close_tab(i)
        elif chosen is close_right:
            for i in range(len(self.tabs) - 1, idx, -1):
                if not self.tabs[i]["pinned"]:
                    self.close_tab(i)
        elif chosen is close_left:
            for i in range(idx - 1, -1, -1):
                if not self.tabs[i]["pinned"]:
                    self.close_tab(i)
        elif chosen is split:
            self.enter_split(idx)

    # ---------------- Central (⚙) ----------------
    def _open_settings(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Central")
        dlg.resize(320, 600)
        layout = QVBoxLayout(dlg)

        def _btn(text: str, fn) -> QPushButton:
            b = QPushButton(text)
            b.clicked.connect(fn)
            layout.addWidget(b)
            return b

        def _info(title: str, text: str) -> None:
            QMessageBox.information(dlg, title, text)

        def destroy_all() -> None:
            prof = QWebEngineProfile.defaultProfile()
            prof.cookieStore().deleteAllCookies()
            prof.clearHttpCache()
            for tab in self.tabs:
                tab["view"].page().runJavaScript(CLEAR_ALL_STORAGE_JS)
            _info(
                "Segurança Assegurada",
                "Sessão integralmente dizimada.\n\nCookies, Cache, LocalStorage e "
                "SessionStorage do seu motor isolado foram aniquilados em tempo real.",
            )

        def change_identity() -> None:
            self.fp = random_fingerprint()
            QWebEngineProfile.defaultProfile().setHttpUserAgent(self.fp.user_agent)
            for tab in self.tabs:
                self._inject_fingerprint(tab["view"].page())
                tab["view"].reload()
            _info(
                "Identidade Mascarada",
                "Sistema operacional, fuso horário, placa de vídeo (WebGL) e "
                "dispositivo foram rotacionados. A página foi recarregada.",
            )

        def shuffle_canvas() -> None:
            shuffle_canvas_noise(self.fp)
            for tab in self.tabs:
                self._inject_fingerprint(tab["view"].page())
                tab["view"].reload()
            _info("Canvas Hash Derrotado", "Noise Algorithm injetado. A página foi recarregada.")

        def clear_fingerprint() -> None:
            for tab in self.tabs:
                tab["view"].page().runJavaScript(CLEAR_FINGERPRINT_JS)
                try:
                    CdpClient().call_by_index(
                        self.tabs.index(tab), "Network.clearBrowserCookies", {}
                    )
                except Exception:
                    pass
            self.fp = random_fingerprint()
            for tab in self.tabs:
                tab["view"].reload()
            _info(
                "Fingerprints Limpos",
                "Tokens de Fingerprint e Visitor IDs eliminados.\n\n"
                "• 'x-finger' e identificadores de FingerprintJS expurgados.\n"
                "• Identidade de Hardware e Canvas rotacionadas.",
            )

        _btn("Destruir Cookies, LocalStorage e Cache", destroy_all)
        _btn("Mudar Identidade", change_identity)
        _btn("Embaralhar Canvas", shuffle_canvas)
        _btn("Limpar Fingerprint (x-finger)", clear_fingerprint)

        layout.addWidget(QLabel("Otimizador (0-1-2):"))
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setRange(0, 2)
        slider.setValue(self.settings.memory_optimization)
        slider.valueChanged.connect(
            lambda v: (
                setattr(self.settings, "memory_optimization", v),
                self._apply_memory_profile(QWebEngineProfile.defaultProfile()),
                cfg.save_settings(self.settings),
            )
        )
        layout.addWidget(slider)

        layout.addWidget(QLabel("DNS Encriptado (DoH):"))
        doh_combo = QComboBox()
        doh_combo.addItems(list(cfg.DOH_PRESETS))
        doh_combo.setCurrentText(cfg.DOH_URL_TO_LABEL.get(self.settings.doh, doh_combo.itemText(0)))

        def save_doh() -> None:
            self.settings.doh = cfg.DOH_PRESETS[doh_combo.currentText()]
            cfg.save_settings(self.settings)
            _info("DNS Atualizado", "DNS salvo! Feche e reabra o navegador para ativar.")

        doh_combo.setEditable(True)
        layout.addWidget(doh_combo)
        _btn("Salvar DNS (requer restart)", save_doh)

        layout.addWidget(QLabel("Proxy (ex: socks5://ip:porta):"))
        proxy_edit = QLineEdit(self.settings.proxy)
        layout.addWidget(proxy_edit)

        def save_proxy() -> None:
            self.settings.proxy = proxy_edit.text().strip()
            cfg.save_settings(self.settings)
            _info("Proxy Atualizado", "Proxy salvo! Feche e reabra o navegador para ativar.")

        _btn("Salvar Proxy", save_proxy)

        layout.addWidget(QLabel("Buscador Padrão:"))
        search_combo = QComboBox()
        search_combo.addItems(list(cfg.SEARCH_ENGINES))
        search_combo.setCurrentText(self.settings.search_engine)
        layout.addWidget(search_combo)

        def save_search() -> None:
            self.settings.search_engine = search_combo.currentText()
            cfg.save_settings(self.settings)
            _info("Buscador Atualizado", "Buscador salvo! Será usado na próxima pesquisa.")

        _btn("Salvar Buscador", save_search)

        ghost_chk = QCheckBox("Aba Fantasma (Isolamento Severo de Sessão)")
        ghost_chk.setChecked(self.settings.ghost_tab)
        ghost_chk.toggled.connect(
            lambda v: (setattr(self.settings, "ghost_tab", bool(v)), cfg.save_settings(self.settings))
        )
        layout.addWidget(ghost_chk)

        mcp_chk = QCheckBox("Ativar Servidor MCP (Porta 8383 — requer restart)")
        mcp_chk.setChecked(self.settings.mcp_enabled)
        mcp_chk.toggled.connect(
            lambda v: (setattr(self.settings, "mcp_enabled", bool(v)), cfg.save_settings(self.settings))
        )
        layout.addWidget(mcp_chk)

        layout.addWidget(QLabel("─── Transferência de Sessão ───"))
        _btn("↑ Exportar Sessão", lambda: self.export_session(dlg))
        _btn("↓ Importar Sessão", lambda: self.import_session(dlg))
        layout.addStretch(1)
        _btn("Fechar", dlg.accept)
        dlg.exec()

    # ---------------- sessão ----------------
    def export_session(self, parent=None) -> None:
        path, _ = QFileDialog.getSaveFileName(parent or self, "Exportar Sessão do Navegador", "AnonSession.json", "Arquivo JSON (*.json)")
        if not path:
            return
        cookies: dict = {"cookies": []}
        try:
            cookies = CdpClient().call_by_index(0, "Network.getAllCookies", {})
        except Exception:
            pass
        storages: list[dict] = []
        for tab in self.tabs:
            view = tab["view"]
            url = view.url().toString()
            if not url or url.startswith(("edge://", "about:", "data:")):
                continue
            try:
                local = self._js_blocking(view, COLLECT_LOCAL_STORAGE_JS) or "{}"
                session_s = self._js_blocking(view, COLLECT_SESSION_STORAGE_JS) or "{}"
                doc_cookie = self._js_blocking(view, COLLECT_DOCUMENT_COOKIE_JS) or ""
                import json as _json

                storages.append(
                    {
                        "url": url,
                        "localStorage": _json.loads(local) if isinstance(local, str) else local,
                        "sessionStorage": _json.loads(session_s) if isinstance(session_s, str) else session_s,
                        "documentCookie": doc_cookie,
                    }
                )
            except Exception:
                continue
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\ufeff" + dump_session(cookies, storages))
            QMessageBox.information(
                parent or self,
                "Export Concluído",
                "Sessão exportada com sucesso!\n\n• Cookies de todos os domínios\n"
                "• LocalStorage por aba\n• SessionStorage por aba\n• Document Cookies",
            )
        except OSError as exc:
            QMessageBox.critical(parent or self, "Erro", f"Erro ao salvar o arquivo de sessão: {exc}")

    def import_session(self, parent=None) -> None:
        path, _ = QFileDialog.getOpenFileName(parent or self, "Importar Sessão do Navegador", "", "Arquivo JSON (*.json)")
        if not path:
            return
        if not self.tabs:
            QMessageBox.critical(parent or self, "Erro", "Nenhuma aba aberta para importar.")
            return
        try:
            with open(path, encoding="utf-8-sig") as f:
                cookies_obj, storages = parse_session(f.read())
        except (OSError, ValueError) as exc:
            QMessageBox.critical(parent or self, "Erro", f"Arquivo de sessão inválido: {exc}")
            return
        cookies_imported = 0
        storages_imported = 0
        client = CdpClient()
        for cookie in (cookies_obj.get("cookies") or []):
            try:
                client.call_by_index(0, "Network.setCookie", cookie)
                cookies_imported += 1
            except Exception:
                continue
        tab_urls = [t["view"].url().toString() for t in self.tabs]
        for storage in storages:
            idx = find_tab_for_storage(tab_urls, storage.get("url", ""))
            view = self.tabs[idx]["view"]
            for script in injection_js_for_storage(storage):
                view.page().runJavaScript(script)
            storages_imported += 1
        QMessageBox.information(
            parent or self,
            "Import Concluído",
            f"Sessão importada com sucesso!\n\n• {cookies_imported} cookies restaurados\n"
            f"• {storages_imported} storages de abas injetados\n\nRecarregue as páginas para efetivar completamente.",
        )

    # ---------------- Bridge (API 8383) ----------------
    def _poll_bridge(self) -> None:
        while True:
            try:
                req = BRIDGE.queue.get_nowait()
            except Empty:
                return
            try:
                self._handle_bridge(req)
            except Exception:
                req.result = traceback.format_exc()
                req.success = False
                req.done.set()

    def _complete(self, req: BridgeRequest, success: bool, result: Any) -> None:
        req.success = success
        req.result = result
        req.done.set()

    def _handle_bridge(self, req: BridgeRequest) -> None:
        op, p = req.op, req.payload
        if op == "list_tabs":
            out = []
            for i, tab in enumerate(self.tabs):
                view = tab["view"]
                out.append({"index": i, "url": view.url().toString(), "title": view.title() or "Nova Guia"})
            self._complete(req, True, out)
        elif op == "get_html":
            idx = int(p.get("index", 0))
            if not (0 <= idx < len(self.tabs)):
                self._complete(req, False, "índice inválido")
                return
            view = self.tabs[idx]["view"]
            view.page().runJavaScript(
                "document.documentElement.outerHTML",
                lambda r, req=req: self._complete(req, True, r),
            )
        elif op == "execute_js":
            idx = int(p.get("index", 0))
            if not (0 <= idx < len(self.tabs)):
                self._complete(req, False, "índice inválido")
                return
            # Via CDP quando disponível (Runtime.evaluate com awaitPromise),
            # senão via runJavaScript do Qt — mesmo resultado do C++.
            ws_url = self._cdp_ws_for_tab(idx)
            if ws_url:
                try:
                    res = CdpClient().call_ws(
                        ws_url, "Runtime.evaluate",
                        {"expression": p.get("script", ""), "awaitPromise": True, "returnByValue": True},
                    )
                    self._complete(req, True, res)
                    return
                except Exception:
                    pass
            view = self.tabs[idx]["view"]
            view.page().runJavaScript(
                p.get("script", ""), lambda r, req=req: self._complete(req, True, r)
            )
        elif op == "navigate":
            idx = int(p.get("index", 0))
            if not (0 <= idx < len(self.tabs)):
                self._complete(req, False, "índice inválido")
                return
            self.tabs[idx]["view"].setUrl(QUrl(p.get("url", "")))
            self._complete(req, True, {"status": "ok"})
        elif op == "new_tab":
            url = p.get("url") or cfg.home_url(self.settings)
            self.new_tab(url)
            self._complete(req, True, {"status": "ok"})
        elif op == "close_tab":
            idx = int(p.get("index", 0))
            if not (0 <= idx < len(self.tabs)):
                self._complete(req, False, "índice inválido")
                return
            self.close_tab(idx)
            self._complete(req, True, {"status": "ok"})
        elif op == "cdp":
            idx = int(p.get("index", 0))
            ws_url = self._cdp_ws_for_tab(idx)
            if not ws_url:
                self._complete(req, False, "alvo CDP não encontrado")
                return
            try:
                res = CdpClient().call_ws(ws_url, p.get("method", ""), p.get("params") or {})
                self._complete(req, True, res)
            except Exception as exc:
                self._complete(req, False, str(exc))
        elif op == "screenshot":
            idx = int(p.get("index", 0))
            if not (0 <= idx < len(self.tabs)):
                self._complete(req, False, "índice inválido")
                return
            # CDP Page.captureScreenshot primeiro (qualidade real da página);
            # fallback: grab() da view.
            ws_url = self._cdp_ws_for_tab(idx)
            if ws_url:
                try:
                    import base64

                    res = CdpClient().call_ws(ws_url, "Page.captureScreenshot", {"format": "png"})
                    path = cfg.screenshot_path()
                    path.write_bytes(base64.b64decode(res.get("data", "")))
                    self._complete(req, True, str(path))
                    return
                except Exception:
                    pass
            pix = self.tabs[idx]["view"].grab()
            path = cfg.screenshot_path()
            pix.save(str(path), "PNG")
            self._complete(req, True, str(path))
        else:
            self._complete(req, False, f"operação desconhecida: {op}")


def run(headless: bool = False, no_mcp: bool = False, api_port: int = 8383) -> int:
    """Ponto de entrada do navegador.

    - ``headless=False`` (padrão): abre a janela.
    - ``headless=True``: sem janela — o backend do navegador roda com
      ``QT_QPA_PLATFORM=offscreen`` e o MCP fica disponível via stdio,
      então dá para usar o MCP sem a UI (``python run.py --headless``).
    - O MCP/API sobe sozinho, salvo ``--no-mcp``: o padrão de
      ``Settings.mcp_enabled`` é True e o modo headless força ligado.
    """
    settings = cfg.load_settings()
    # Perfil efêmero: apagado a cada inicialização, como no original.
    shutil.rmtree(cfg.profile_dir(), ignore_errors=True)
    flags = cfg.chromium_flags(settings)
    if headless:
        # Sem display: Qt offscreen + Chromium sem GPU.
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        flags += ["--disable-gpu", "--disable-dev-shm-usage"]
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(flags)
    app = QApplication([])  # []: as flags --headless/--no-mcp são nossas, não do Qt
    fingerprint = random_fingerprint()
    window = MainWindow(settings, fingerprint, headless=headless)
    if not headless:
        window.show()
    window.new_tab(cfg.home_url(settings))
    mcp_on = (settings.mcp_enabled or headless) and not no_mcp
    if mcp_on:
        from .api_server import start_api_server

        start_api_server(port=api_port)
        from .cdp import CdpEventListener

        listener = CdpEventListener(lambda kind, data: NETWORK_LOG.log(kind, data))
        listener.start()
        # MCP via stdio numa thread daemon: o cliente MCP pode apontar
        # direto para `python run.py` / `python run.py --headless`.
        # Nada aqui escreve no stdout além do JSON-RPC do MCP.
        from . import mcp_server

        def _mcp_stdio_loop() -> None:
            mcp_server.main()
            if headless:
                # Cliente MCP fechou o stdin: o servidor headless encerra.
                _app = QApplication.instance()
                if _app is not None:
                    _app.quit()

        threading.Thread(target=_mcp_stdio_loop, name="anonsite-mcp-stdio", daemon=True).start()
    return app.exec()
