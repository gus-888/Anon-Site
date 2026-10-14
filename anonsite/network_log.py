"""Log de rede (anel de no máximo 200 entradas, como o C++).

O original guardava ``{"type": "Request"|"Response", "data": {...}}`` via
CDP ``Network.requestWillBeSent`` / ``Network.responseReceived`` e servia
em ``GET /network``. Aqui a estrutura é idêntica para o MCP não mudar.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any

MAX_ENTRIES = 200


class NetworkLog:
    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)

    def log(self, entry_type: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._entries.append({"type": entry_type, "data": data})

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
