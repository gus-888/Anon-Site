# AnonSite — Python

Inclui o navegador com 50 ferramentas para controlar o navegador via IA, que pode rodar **com ou sem a interface gráfica**.

---

## Recursos

- **Config (⚙)**: destruir cookies/cache/storage, mudar identidade,
  embaralhar canvas, limpar fingerprint (`x-finger`), DoH, proxy, buscador,
  aba Fantasma, exportar/importar sessão.
- **Sessão**: exporta/importa `AnonSession.json` (cookies + storages).
- **API HTTP** em `http://127.0.0.1:8383` (só localhost): abas, JS, CDP,
  rede, screenshot.
- **Servidor MCP** (JSON-RPC via stdio, 50 ferramentas): abas, JS, CDP,
  cookies, storage, rede, HAR, JWT, DNS, TLS, redirects, OpenAPI, nmap,
  theHarvester, WhatWeb, Nuclei.

---

## Requisitos

| Requisito | Detalhe |
|---|---|
| Python | **3.10 ou superior** |
| pip + venv | Vêm com o Python |
| Linux | Libs de sistema do QtWebEngine (ver instalação abaixo) |
| Windows | Nada além do Python + pip |
| Espaço | ~300 MB (PyQt6-WebEngine traz o Chromium) |

### O que tem no `requirements.txt`

| Pacote | Para quê |
|---|---|
| `PyQt6` | Interface (janela, abas, botões) |
| `PyQt6-WebEngine` | O Chromium embutido que renderiza as páginas |
| `websocket-client` | Cliente do CDP (Chrome DevTools Protocol) |

Dependências opcionais (não estão no `requirements.txt`):

| Pacote | Para quê |
|---|---|
| `pytest` | Rodar os testes (`pip install pytest`) |
| `cryptography` | Detalhes completos do certificado TLS no `check_ssl_cert` |

---

## Instalação

### Linux

```bash
# 1. (Debian/Ubuntu) Libs de sistema do QtWebEngine
sudo apt update
sudo apt install python3 python3-venv python3-pip \
  libgl1 libegl1 libxkbcommon0 libdbus-1-3 libfontconfig1

# 2. Entre na pasta do projeto
cd anonsite-python

# 3. Crie e ative o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# 4. Instale os requirements
pip install -r requirements.txt
```

> Outras distros: instale o equivalente a `libGL`, `libEGL`,
> `libxkbcommon`, `dbus` e `fontconfig` pelo gerenciador de pacotes da
> sua distro (ex.: `dnf` no Fedora, `pacman` no Arch).

### Windows

```powershell
# 1. Entre na pasta do projeto
cd anonsite-python
```

> Se `py` não existir, use `python` no lugar em todos os comandos.

```powershell
# 2. Instale os requirements
pip install -r requirements.txt
```

### Verificar a instalação

```bash
# Linux
python -m pytest tests/ -q
# Windows (PowerShell, com o venv ativo)
py -m pytest tests/ -q
# Esperado: 20 passed
```

> Sem `pytest`? Instale com `pip install pytest` (só para testes).

---

## Como usar

### Navegador com interface

```bash
# Linux
python run.py

# Windows (PowerShell)
py run.py
```

O MCP e a API sobem **sozinhos** junto com o navegador — não é preciso
ativar nada. Para abrir sem MCP/API:

```bash
python run.py --no-mcp     # Linux
py run.py --no-mcp         # Windows
```

### MCP sem a interface (headless)

Um único comando sobe o backend do navegador + API + MCP via stdio, sem
abrir janela. É o modo recomendado para usar o MCP:

```bash
# Linux
python run.py --headless

# Windows (PowerShell)
py run.py --headless
```

Aponte o cliente MCP diretamente para esse comando:

```json
{
  "mcpServers": {
    "anonsite": {
      "command": "python",
      "args": ["run.py", "--headless"],
      "cwd": "/caminho/para/anonsite-python"
    }
  }
}
```

No Windows, use `"command": "py"` (ou o caminho completo do
`python.exe` do venv, ex.:
`"command": "C:\\caminho\\para\\anonsite-python\\.venv\\Scripts\\python.exe"`).

### MCP com o navegador já aberto (modo alternativo)

Se o navegador já estiver rodando (com UI ou headless), o cliente MCP
pode usar o servidor MCP avulso, que conversa com a API:

```json
{
  "mcpServers": {
    "anonsite": {
      "command": "python",
      "args": ["-m", "anonsite.mcp_server"],
      "cwd": "/caminho/para/anonsite-python"
    }
  }
}
```

### Opções do `run.py`

```bash
python run.py --help
```

| Opção | O que faz |
|---|---|
| *(nenhuma)* | Navegador com UI + API + MCP |
| `--headless` | Sem janela: backend + API + MCP via stdio |
| `--no-mcp` | Só o navegador, sem API/MCP |
| `--port 8383` | Porta da API HTTP (padrão: 8383) |

Também funciona `python -m anonsite` com as mesmas opções.

### API HTTP direto (porta 8383)

```bash
# Listar abas
curl http://127.0.0.1:8383/tabs

# Executar JavaScript na aba 0
curl -X POST http://127.0.0.1:8383/execute \
  -H "Content-Type: application/json" \
  -d '{"index": 0, "script": "document.title"}'

# Screenshot da aba 0 (devolve o caminho do PNG)
curl "http://127.0.0.1:8383/screenshot?index=0"
```

(`curl` já vem no Windows 10/11 e no Linux. A API só escuta em
`127.0.0.1`, nunca na rede.)

### Testar o MCP no terminal

```bash
# Linux
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python -m anonsite.mcp_server
```

```powershell
# Windows (PowerShell)
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' |
  py -m anonsite.mcp_server
```

Esperado: `initialize` com `serverInfo.name = "anonsite-mcp"` e
`tools/list` com **50 ferramentas**.

---

## Estrutura do projeto

```
anonsite-python/
├── run.py                  # entrada: python run.py [--headless] [--no-mcp] [--port]
├── requirements.txt        # PyQt6, PyQt6-WebEngine, websocket-client
├── pyproject.toml          # metadados (pip install .)
├── README.md               # este arquivo
├── COMO-USAR.md            # guia prático de uso
├── EXPLICACAO.md           # como funciona por dentro
├── anonsite/
│   ├── __main__.py         # CLI (argparse) — não exige Qt para --help
│   ├── browser.py          # janela, abas, split, downloads, Central, Bridge
│   ├── config.py           # config em JSON (~/.config/anonsite/ ou %APPDATA%)
│   ├── fingerprint.py      # 5 perfis + JS anti-tracking
│   ├── session.py          # export/import de sessão (AnonSession.json)
│   ├── cdp.py              # cliente CDP via remote-debugging (porta 9222)
│   ├── network_log.py      # log de rede (máx. 200 entradas)
│   ├── api_server.py       # API HTTP 127.0.0.1:8383
│   ├── mcp_server.py       # servidor MCP stdio (50 ferramentas)
│   └── tools_external.py   # nmap, DNS, TLS, JWT, HAR, OpenAPI, redirects
└── tests/                  # testes (pytest)
```

---

## Configuração

As configurações ficam num único JSON:

- **Linux:** `~/.config/anonsite/config.json`
- **Windows:** `%APPDATA%\anonsite\config.json`

Elas são editadas pela **Central (⚙)** dentro do navegador (DoH, proxy,
buscador, aba Fantasma, MCP, otimizador). Na primeira execução, os
arquivos legados `Anon*.txt` do diretório temporário são migrados
automaticamente, se existirem.

---

## Solução de problemas

| Sintoma | O que fazer |
|---|---|
| `ModuleNotFoundError: PyQt6` | Ative o venv e rode `pip install -r requirements.txt` de novo. |
| `libEGL.so.1` / `libXtst` não encontrado (Linux) | Instale as libs de sistema da seção de instalação. |
| `py` não é reconhecido (Windows) | Use `python` no lugar de `py`. |
| Páginas dando OFFLINE | Suspeite do proxy (IP/porta) ou do DoH; desative e reinicie. |
| MCP/API não responde | O `run.py` precisa estar rodando (com ou sem UI). Com `--no-mcp`, a API/MCP ficam desligados. |
| `nmap` / `nuclei` / etc. não encontrado no MCP | Instale a ferramenta no sistema (no `PATH`) ou informe `custom_path` na chamada. |

---

## Segurança

As ferramentas MCP de segurança (nmap, Nuclei, fuzzing, etc.) servem
para auditar **sistemas que você tem autorização para testar**. Os
comandos externos rodam via `subprocess` **sem shell**.

---
