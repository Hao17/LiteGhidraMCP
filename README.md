# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version Notice**:
> - **Current branch (main)**: Ghidra 12.0+ / PyGhidra version
> - **Ghidra 11.x users**: Please switch to [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or use [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, providing AI systems with programmatic access to Ghidra's reverse engineering capabilities.

### Highlights

- **6 aggregated MCP tools** — Single entry, pattern-dispatched to 50+ APIs. No tool sprawl.
- **Version control + AI/human collaboration** — Multiple AI agents and human analysts work on the same binary via Ghidra Server, with full version history.
- **Multi-binary cross-analysis** — Spin up multiple clients against different binaries in one project. Ideal for scenarios like VMP unpacking, DLL-EXE interaction tracing, and multi-module firmware.
- **GUI, headless, and Docker** — Same API codebase across all modes. Docker Server-Client for fully autonomous AI-driven analysis.

## Quick Start Guide

**Recommended: Docker Deployment (One Command)** ⭐
- → [Docker Server-Client Mode](#docker-deployment): AI + GUI collaboration, per-client user isolation
- One command setup, auto SSH key generation
- Best for production, team collaboration, multiple AI agents

**Alternative: GUI Mode**
- → [Run in Ghidra GUI](#gui-mode): Run script directly in Ghidra CodeBrowser
- No Docker needed, simplest for single-user analysis

After setup, → [Configure AI Client](#configure-ai-client) to connect your AI tools.

---

## Docker Deployment

### Separated Server-Client Mode ⭐ Recommended

AI (Docker) + GUI (Human) collaboration with one command. Each client binds to one REPO/BINARY (name or repo path) at startup, and runtime switching is intentionally unsupported.

> **Apple Silicon / ARM hosts**:
> The official Ghidra distribution currently does not ship a `linux_arm_64` decompiler binary. Run the Bridge containers as `linux/amd64`; the compose files in this repo now default to that platform to avoid `Could not find decompiler executable`.

```bash
cd docker/

# First time setup
cp .env.example .env
vim .env  # Set GHIDRA_DATA_DIR (e.g., ~/ghidra-data)

# Start server
make server-up

# Start client (REPO required, BINARY recommended)
make client-up REPO=test BINARY=my_binary                       # Open existing binary
make client-up REPO=test BINARY=38.1.0/my_binary               # Open binary by repo path
make client-up REPO=test BINARY=my_binary BINARY_FILE=~/a.bin  # Import + open

# Second client on different ports (8813/8814)
make client2-up REPO=test BINARY=modules/other_binary
```

**What happens:**
- Ghidra Server starts on port `13100` with `root` user (random password in logs)
- Each client auto-generates SSH key and registers as `bridge-<N>`
- Repository `mcp-projects` is auto-created
- HTTP API: `http://localhost:8803`, MCP SSE: `http://localhost:8804/sse`

**Connect Ghidra GUI:**

1. File → New Project → **Shared Project**
2. Server: `localhost:13100`
3. User: `root`, **uncheck** "Use PKI authentication"
4. Password: from `make server-logs` (look for `root (password): ...`)
5. Repository: `mcp-projects`

**Useful commands:**

```bash
make server-logs      # View server logs (find root password here)
make server-users     # List registered users
make client-logs      # View client logs
make down-separated   # Stop everything
make server-clean     # Remove all data (destructive)
```

**Detailed guide**: [docker/QUICKSTART.md](docker/QUICKSTART.md#separated-server-client-mode-recommended-for-aigui-collaboration)

### Local Project Mode (Automation Only)

Mount a local `.gpr` project into Docker. **GUI cannot open it simultaneously.**

```bash
cd docker && cp .env.example .env
# Edit .env: set HOST_PROJECT_PATH, PROJECT_NAME, PROJECT_MODE=local
docker-compose up -d
```

### External Ghidra Server

Connect to an existing Ghidra Server with `PROJECT_MODE=server`. See [docker/QUICKSTART.md](docker/QUICKSTART.md) for configuration details.

---

## GUI Mode

**Requirements:** Ghidra 12.0+ (the script depends on PyGhidra and will not run under the default Jython/Java runtime).

### 1. Launch Ghidra with PyGhidra

The script must be loaded by the **PyGhidra** plugin. Use the dedicated launcher shipped with Ghidra:

```bash
# macOS / Linux
<ghidra_install>/support/pyghidraRun

# Windows
<ghidra_install>\support\pyghidraRun.bat
```

The first launch provisions a dedicated Python venv (kept outside your Ghidra install dir):

| OS | Default venv location |
|---|---|
| macOS | `~/Library/ghidra/ghidra_<VERSION>_PUBLIC/venv/` |
| Linux | `~/.config/ghidra/ghidra_<VERSION>_PUBLIC/venv/` |
| Windows | `%APPDATA%\ghidra\ghidra_<VERSION>_PUBLIC\venv\` |

If you previously used Ghidra without PyGhidra and the venv looks broken, delete that directory and relaunch — `pyghidraRun` will rebuild it.

### 2. Install Bridge dependencies into the PyGhidra venv

The Bridge spawns an SSE proxy subprocess that imports `mcp`, `uvicorn`, `httpx`. They must live in the **PyGhidra venv** (not your system Python):

```bash
# macOS example — adjust the version segment for your install
~/Library/ghidra/ghidra_12.0.3_PUBLIC/venv/bin/python3 -m pip install -r requirements.txt
```

Verify:

```bash
~/Library/ghidra/ghidra_12.0.3_PUBLIC/venv/bin/python3 -c "from mcp.server.fastmcp import FastMCP; import uvicorn, httpx"
```

### 3. Run the script

1. Open a binary in Ghidra CodeBrowser
2. Open Script Manager (`Window` → `Script Manager`)
3. **Add script path** (first time): Click "Manage Script Directories" (folder icon) → `+` → select this project root → OK
4. Run `ghidra_mcp_server.py` (do **not** run `docker_only_ghidra_mcp_server.py` — that one is Docker-only and will error on container paths)
5. Confirm in the script console:
   ```
   [Ghidra-MCP-Bridge] HTTP Server: http://127.0.0.1:8803
   [Ghidra-MCP-Bridge] MCP Server:  http://127.0.0.1:8804/sse
   [Ghidra-MCP-Bridge] Current Loaded Program: <name> (...)
   ```
   If you see `MCP proxy failed to start` with `ModuleNotFoundError: No module named 'mcp'`, step 2 was missed or installed into the wrong Python.

---

## Configure AI Client

After starting the Bridge (Docker or GUI), connect your AI client to the MCP SSE endpoint.

Default endpoint: `http://localhost:8804/sse` (Docker) or `http://127.0.0.1:8804/sse` (GUI)

### Available MCP Tools

- **ghidra_overview**: Comprehensive binary survey — metadata, memory layout, statistics, key functions, imports/exports, strings (recommended first call)
- **ghidra_search**: Search functions, symbols, strings, cross-references, etc.
- **ghidra_view**: Decompilation/disassembly/memory viewing
- **ghidra_list**: Symbol list browsing
- **ghidra_edit**: Unified editing (rename, datatype, comments)
- **ghidra_version**: Version management — commit/log/rollback/revert (Server mode only, conditionally registered)

### Coco

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

### Claude Desktop

Edit config file (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "sse",
      "url": "http://127.0.0.1:8804/sse"
    }
  }
}
```

Save and restart Claude Desktop.

### Claude Code

```bash
claude mcp add --transport sse ghidra http://127.0.0.1:8804/sse
```

---

## Advanced Options

### HTTP API

```bash
curl http://127.0.0.1:8803/api/v1/overview
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"
curl "http://127.0.0.1:8803/api/memory/read?address=0x401000&length=256"
```

For complete API documentation, see [CLAUDE.md](CLAUDE.md).

### Environment Variables

```bash
export GHIDRA_MCP_HOST=127.0.0.1      # HTTP API host (default: 127.0.0.1)
export GHIDRA_MCP_PORT=8803           # HTTP API port (default: 8803)
export GHIDRA_MCP_SSE_PORT=8804       # MCP SSE port (default: 8804)
export PROGRAM_NAME=""                # Program name or repo path to open at startup (default: first available)
```

### Multi-Program Analysis

Use different ports in different Ghidra instances, then configure multiple MCP servers in your AI client:

```json
{
  "mcpServers": {
    "ghidra-binary1": { "type": "sse", "url": "http://127.0.0.1:8804/sse" },
    "ghidra-binary2": { "type": "sse", "url": "http://127.0.0.1:8806/sse" }
  }
}
```

## Project Structure

```
Bridge/
├── ghidra_mcp_server.py           # GUI mode server (Ghidra Script Manager)
├── docker_only_ghidra_mcp_server.py  # Docker/Headless mode server (PyGhidra) — DO NOT run in GUI Script Manager
├── api/                           # API modules (basic_info, search, view, memory, comment, rename, datatype, version, ...)
├── api_v1/                        # AI-friendly aggregated API (overview, search, view, list, edit)
├── scripts/
│   ├── mcp_sse_proxy.py           # MCP SSE proxy (subprocess)
│   └── mcp_stdio.py               # MCP stdio mode (standalone)
└── docker/                        # Docker deployment (Server-Client mode)
```

## Troubleshooting

**Server won't start?**
- Confirm a binary file is opened in Ghidra CodeBrowser
- Verify you're using Ghidra 12.0+ (built-in PyGhidra support)

**AI client can't connect?**
- Confirm the server is running (check Ghidra Console output or Docker logs)
- Verify the port number is correct (SSE default: 8804)
- Restart the client (Claude Desktop / Coco / Claude Code)

## Development

For detailed API development guide and architecture documentation, see [CLAUDE.md](CLAUDE.md).
