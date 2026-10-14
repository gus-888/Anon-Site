#!/usr/bin/env python3
"""Ponto de entrada: `python run.py` (equivale a `python -m anonsite`).

- `python run.py` → navegador com UI + API + MCP (o MCP sobe sozinho).
- `python run.py --headless` → sem UI: backend + API + MCP via stdio.
  É assim que se usa o MCP sem a UI — o cliente MCP aponta para este comando.
- `python run.py --no-mcp` → só o navegador, sem API/MCP.
- `python run.py --help` → lista as opções (não exige PyQt6 instalado).
"""
from anonsite.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
