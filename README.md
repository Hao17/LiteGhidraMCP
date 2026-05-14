# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version Notice**:
> - **Current branch (main)**: Ghidra 12.0+ / PyGhidra version
> - **Ghidra 11.x users**: Please switch to [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or use [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, providing AI systems with programmatic access to Ghidra's reverse engineering capabilities.

### Highlights

- **7 MCP tools** — Single entry, pattern-dispatched to 50+ APIs. No tool sprawl.
- **Version control + AI/human collaboration** — Multiple AI agents and human analysts work on the same binary via Ghidra Server, with full version history.
- **Multi-binary cross-analysis** — Spin up multiple clients against different binaries in one project. Ideal for scenarios like VMP unpacking, DLL-EXE interaction tracing, and multi-module firmware.
- **AI-friendly** — Clone the repo, install the skill, and let Claude Code / Codex handle the rest — start server, spin up clients, configure MCP, and begin analysis.

---

## Quick Start Guide

### Let AI Do It ⭐

```bash
git clone https://github.com/Hao17/LiteGhidraMCP.git && cd LiteGhidraMCP
pip install -e .
gmcp install -d . skill claude-code   # or: codex / cursor / copilot
```

Then just tell your AI:

> *"Help me analyze ~/Downloads/firmware.bin"*

It knows how to start the server, import the binary, configure MCP, and begin analysis.

### Manual Setup

**Docker Server-Client Mode** (recommended)
- → [Docker Deployment](#docker-deployment): AI + GUI collaboration, multi-client
- One command setup, auto SSH key generation, interactive admin registration

**GUI Mode** (no Docker)
- → [GUI Mode](#gui-mode): Run script directly in Ghidra CodeBrowser
- Simplest for single-user analysis

After manual setup, → [Connect AI](#connect-ai) to wire up MCP.

---

## Docker Deployment

### Install CLI

```bash
pip install -e .
```

This installs the `gmcp` command — a CLI wrapper for all Docker operations. Run `gmcp --help` to see available commands.

### Separated Server-Client Mode ⭐ Recommended

AI (Docker) + GUI (Human) collaboration with one command. Each client binds to one REPO/BINARY (name or repo path) at startup, and runtime switching is intentionally unsupported.

> **Apple Silicon / ARM hosts**:
> The official Ghidra distribution currently does not ship a `linux_arm_64` decompiler binary. Run the Bridge containers as `linux/amd64`; the compose files in this repo now default to that platform to avoid `Could not find decompiler executable`.

```bash
# Start server (first run auto-creates config and prompts to register an admin)
gmcp server up

# Create the repository (admin-owned model: clients cannot create repos)
gmcp server repo create test

# Start client (--repo required, --binary recommended)
gmcp client start 1 --repo test --binary my_binary                          # Open existing binary
gmcp client start 1 --repo test --binary 38.1.0/my_binary                  # Open binary by repo path
gmcp client start 1 --repo test --binary my_binary --binary-file ~/a.bin   # Import + open

# Second client on different ports (8813/8814)
gmcp client start 2 --repo test --binary modules/other_binary

# Stable named identity (instead of the default ephemeral UUID)
gmcp client start 1 --repo test --binary my_binary --user alice
```

#### What happens

- Ghidra Server starts on port `13100`
- **First run only**: prompts you to register an admin user (username + password) for GUI access. The admin is auto-granted `+a` on every repository.
- `gmcp server repo create` provisions the repo via the `bridgectl` SSH identity (auto-generated on first `server up`)
- Each `gmcp client start` generates a fresh ephemeral identity (`u-<hex>`) with its own SSH keypair and a `+w` grant on the chosen repo. Pass `--user <name>` to reuse a stable identity instead.
- HTTP API: `http://localhost:8803`, MCP SSE: `http://localhost:8804/sse`

#### Connect Ghidra GUI

1. File → New Project → **Shared Project**
2. Server: `localhost:13100`
3. User: the admin username you registered (or `root`), **uncheck** "Use PKI authentication"
4. Password: the one you set during registration (for `root`: check `gmcp server logs`)
5. Select a repository

#### Useful commands

```bash
gmcp server logs              # View server logs
gmcp server users             # List registered users
gmcp server add-user <name>   # Add another password admin (prompts for password)
gmcp server repos             # List repositories with their ACL grants
gmcp server repo create <r>   # Create a repository (admin-owned)
gmcp server repo grant <user> <repo> +w  # Grant a non-admin SSH identity write access
gmcp client logs 1            # View client 1 logs
gmcp client stop 1            # Stop client 1 (also tears down its ephemeral identity)
gmcp down                     # Stop everything (server + all clients)
gmcp server clean             # Remove all data (destructive, re-prompts admin on next start)
gmcp info                     # Show current configuration
gmcp troubleshoot check       # Diagnose problems
```

> **Detailed guide**: [docker/QUICKSTART.md](docker/QUICKSTART.md)

### Local Project Mode (Automation Only)

Mount a local `.gpr` project into Docker. **GUI cannot open it simultaneously.**

```bash
cd docker && cp .env.example .env
# Edit .env: set HOST_PROJECT_PATH, PROJECT_NAME, PROJECT_MODE=local
docker-compose up -d
```

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

## Connect AI

### Install Skill (Recommended)

The skill teaches your AI agent the full workflow — how to start/stop Docker services, configure MCP connections, and use all Ghidra MCP tools. Once installed, the AI can manage everything autonomously.

```bash
# Run from your project directory (-d specifies target project)
gmcp install -d . skill claude-code    # Claude Code → .claude/commands/
gmcp install -d . skill codex          # OpenAI Codex → AGENTS.md
gmcp install -d . skill cursor         # Cursor → .cursor/rules/ghidra-mcp.md
gmcp install -d . skill copilot        # GitHub Copilot → .github/copilot-instructions.md
```

> What the skill covers: [skills/SKILL.md](skills/SKILL.md)

### Configure MCP Connection

If you just need to wire up an AI client to a running Bridge instance:

```bash
gmcp install mcp claude-code        # Claude Code
gmcp install mcp claude-desktop     # Claude Desktop
gmcp install mcp coco               # Coco

# Multi-client (auto-calculates port from client N)
gmcp install mcp claude-code --client 2   # → ghidra-2 on port 8814
```

<details>
<summary>Manual MCP configuration</summary>

**Claude Code:**

```bash
claude mcp add --transport sse ghidra http://127.0.0.1:8804/sse
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

**Coco:**

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

Default endpoint: `http://127.0.0.1:8804/sse`. Multi-client: Client N → port `8800+(N-1)*10+4`.

</details>

### MCP Tools

| Tool | Description |
|------|-------------|
| **ghidra_overview** | Binary survey — metadata, memory layout, key functions, imports/exports, strings |
| **ghidra_search** | Search functions, symbols, strings, cross-references, bytes, instructions |
| **ghidra_view** | Decompilation / disassembly / memory viewing |
| **ghidra_list** | Symbol list browsing (functions, classes, imports, exports, ...) |
| **ghidra_edit** | Rename, set datatypes, add comments (batch supported) |
| **ghidra_exec** | Execute custom Python/Java scripts with full Ghidra API access |
| **ghidra_version** | Version log / rollback / revert (Server mode only) |

---

## Advanced Options

### HTTP API

```bash
curl http://127.0.0.1:8803/api/v1/overview
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"
curl "http://127.0.0.1:8803/api/memory/read?address=0x401000&length=256"
```

> For complete API documentation, see [CLAUDE.md](CLAUDE.md).

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
    "ghidra-binary2": { "type": "sse", "url": "http://127.0.0.1:8814/sse" }
  }
}
```

---

## Project Structure

```
Bridge/
├── ghidra_mcp_server.py              # GUI mode server (Ghidra Script Manager)
├── docker_only_ghidra_mcp_server.py  # Docker/Headless mode server (PyGhidra) — DO NOT run in GUI
├── api/                              # API modules (basic_info, search, view, memory, comment, rename, datatype, version, ...)
├── api_v1/                           # AI-friendly aggregated API (overview, search, view, list, edit)
├── cli/                              # gmcp CLI (pip install -e .)
├── scripts/
│   ├── mcp_sse_proxy.py              # MCP SSE proxy (subprocess)
│   └── mcp_stdio.py                  # MCP stdio mode (standalone)
├── skills/                           # AI skill document (SKILL.md, installed by `gmcp install skill`)
├── utils/                            # Shared utilities
└── docker/                           # Docker deployment (Server-Client mode)
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

> For detailed API development guide and architecture documentation, see [CLAUDE.md](CLAUDE.md).
