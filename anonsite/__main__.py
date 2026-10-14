"""Ponto de entrada do pacote.

``python -m anonsite`` — abre o navegador (com UI).
``python -m anonsite --headless`` — sem UI: backend do navegador + API + MCP via stdio.
``python -m anonsite.mcp_server`` — só o MCP via stdio (exige o navegador já rodando).

O parsing de argumentos é stdlib pura e NÃO importa o Qt: ``python run.py --help``
funciona mesmo sem PyQt6 instalado.
"""
from __future__ import annotations

import argparse
import sys


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anonsite",
        description="AnonSite — navegador anônimo em Python (PyQt6 + QtWebEngine).",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Sem janela: roda só o backend do navegador + API + MCP via stdio. "
        "É o modo para usar o MCP sem a UI (ex.: cliente MCP aponta para 'python run.py --headless').",
    )
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="Não sobe a API (porta 8383) nem o servidor MCP.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8383,
        help="Porta da API HTTP do navegador (padrão: 8383).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    from .browser import run

    return run(headless=args.headless, no_mcp=args.no_mcp, api_port=args.port)


if __name__ == "__main__":
    sys.exit(main())
