"""Testes do CLI do run.py — parsing sem importar o Qt."""
import subprocess
import sys
from pathlib import Path

from anonsite import config as cfg
from anonsite.__main__ import parse_args

ROOT = Path(__file__).resolve().parents[1]


def test_parse_defaults():
    args = parse_args([])
    assert args.headless is False
    assert args.no_mcp is False
    assert args.port == 8383


def test_parse_headless_and_port():
    args = parse_args(["--headless", "--port", "9999"])
    assert args.headless is True
    assert args.port == 9999


def test_parse_no_mcp():
    assert parse_args(["--no-mcp"]).no_mcp is True


def test_mcp_enabled_by_default():
    # O run.py sobe o MCP sozinho: o padrão tem de ser ligado.
    assert cfg.Settings().mcp_enabled is True


def test_run_help_without_qt():
    # --help não pode exigir PyQt6 instalado.
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run.py"), "--help"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert "--headless" in proc.stdout
    assert "--no-mcp" in proc.stdout
    assert "--port" in proc.stdout
