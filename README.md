# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version Notice**:
> - **Current branch (main)**: Ghidra 12.0+ / PyGhidra version
> - **Ghidra 11.x users**: Please switch to [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or use [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, providing AI systems with programmatic access to Ghidra's reverse engineering capabilities.

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

AI (Docker) + GUI (Human) collaboration with one command. Each client binds to one REPO/BINARY at startup.

```bash
cd docker/

# First time setup
cp .env.example .env
vim .env  # Set GHIDRA_DATA_DIR (e.g., ~/ghidra-data)

# Start server
make server-up

# Start client (REPO required, BINARY recommended)
make client-up REPO=test BINARY=my_binary                    # Open existing binary
make client-up REPO=test BINARY=my_binary BINARY_FILE=~/a.bin  # Import + open

# Second client on different ports (8813/8814)
make client2-up REPO=test BINARY=other_binary
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

**Requirements:** Ghidra 12.0+ and `pip install -r requirements.txt`

1. Open a binary in Ghidra CodeBrowser
2. Open Script Manager (`Window` → `Script Manager`)
3. **Add script path** (first time): Click "Manage Script Directories" (folder icon) → `+` → select the project root directory → OK
4. Run `ghidra_mcp_server.py`
5. Confirm in log:
   ```
   Server started on http://127.0.0.1:8803
   MCP SSE server started on http://127.0.0.1:8804
   ```

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
export PROGRAM_NAME=""                # Program to open at startup (default: first available)
```

### Multi-Program Analysis

Use different ports in different Ghidra instances, then configure multiple MCP servers in your AI client:

```json
{
  "mcpServers": {
    "ghidra-binary1": { "url": "http://127.0.0.1:8804/sse" },
    "ghidra-binary2": { "url": "http://127.0.0.1:8806/sse" }
  }
}
```

## Project Structure

```
Bridge/
├── ghidra_mcp_server.py           # GUI mode server (Ghidra Script Manager)
├── ghidra_mcp_server_pyghidra.py  # Docker/Headless mode server (PyGhidra)
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
