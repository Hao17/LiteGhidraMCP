# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version Notice**:
> - **Current branch (main)**: Ghidra 12.0+ / PyGhidra version
> - **Ghidra 11.x users**: Please switch to [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or use [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, providing AI systems with programmatic access to Ghidra's reverse engineering capabilities.

## Prerequisites

### 1. Ghidra

**Version requirement**: Ghidra 12.0+

Download: https://ghidra-sre.org/

> **Note**: This project uses Ghidra 12.0+'s built-in PyGhidra support, no additional plugins required.
> If using Ghidra 11.x, please switch to the `ghidra-11-ghidrathon` branch.

### 2. Python Dependencies (for MCP)

**Only required for MCP SSE server and stdio mode.** The Ghidra Bridge itself uses Ghidra 12.0+'s built-in PyGhidra.

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `mcp`: Model Context Protocol SDK
- `uvicorn`: ASGI server (for MCP SSE proxy)
- `httpx`: HTTP client (for Bridge communication)

## Quick Start

### 1. Start Ghidra Bridge

1. Open a binary file in Ghidra CodeBrowser
2. Open Script Manager (`Window` → `Script Manager`)
3. **Add script path** (required for first-time use):
   - Click the **"Manage Script Directories"** button (folder icon) in the top-right corner of Script Manager
   - Click the `+` button
   - Select the project root directory (containing `ghidra_mcp_server.py`)
   - Click OK
4. Locate and run `ghidra_mcp_server.py` in Script Manager
5. Confirm the following messages in the log:
   ```
   Server started on http://127.0.0.1:8803
   MCP SSE server started on http://127.0.0.1:8804
   ```

**Hot Reload:** Running the script again will automatically reload API modules without restarting the server.

### 2. Configure AI Client

Choose the configuration method based on your AI client:

#### Coco

Recommended to use gemini-pro model for internal networks.

```bash
coco mcp add-json ghidra '{"type": "sse", "url": "http://127.0.0.1:8804/sse"}'
```

#### Claude Desktop

Edit Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/settings.json`

Single program configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://127.0.0.1:8804/sse"
    }
  }
}
```

**Multi-program analysis** (configure different ports in different Ghidra instances):

```json
{
  "mcpServers": {
    "ghidra-sdk_v1": {
      "url": "http://127.0.0.1:8804/sse"
    },
    "ghidra-sdk_v2": {
      "url": "http://127.0.0.1:8806/sse"
    }
  }
}
```

Save and restart Claude Desktop to start using Ghidra tools.

#### Claude Code

```bash
claude mcp add --transport sse ghidra-init1 http://127.0.0.1:8804/sse
```

## Available Tools

Once configured, your AI client will automatically gain access to the following Ghidra tools:

- **ghidra_search**: Search functions, symbols, strings, cross-references, etc.
- **ghidra_view**: Decompilation/disassembly viewing
- **ghidra_list**: Symbol list browsing (similar to ls)
- **ghidra_edit**: Unified editing (rename, datatype setting, comments)
- **ghidra_basic_info**: Get basic program information

## Environment Variables (Optional)

Customize ports via environment variables:

```bash
export GHIDRA_MCP_HOST=127.0.0.1      # HTTP API host (default: 127.0.0.1)
export GHIDRA_MCP_PORT=8803           # HTTP API port (default: 8803)
export GHIDRA_MCP_SSE_PORT=8804       # MCP SSE port (default: 8804)
```

**Multi-program analysis:**

To analyze multiple binary files simultaneously, use different ports in different Ghidra instances:

```bash
# First Ghidra instance (analyzing sdk_v1)
export GHIDRA_MCP_PORT=8803
export GHIDRA_MCP_SSE_PORT=8804

# Second Ghidra instance (analyzing sdk_v2)
export GHIDRA_MCP_PORT=8805
export GHIDRA_MCP_SSE_PORT=8806
```

Then add multiple MCP servers to your AI client configuration file (refer to the Claude Desktop multi-program configuration example above).

## HTTP API

The Bridge also provides an HTTP JSON API for testing or integrating with other tools:

```bash
# Get basic program information
curl http://127.0.0.1:8803/api/basic_info

# Search functions
curl "http://127.0.0.1:8803/api/v1/search?q=main&types=functions"

# Decompile function
curl "http://127.0.0.1:8803/api/v1/view?q=main&type=decompile"

# Rename function
curl -X POST http://127.0.0.1:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "main"}'

# Hot reload API modules
curl http://127.0.0.1:8803/_reload

# Shutdown server
curl http://127.0.0.1:8803/_shutdown
```

For complete API documentation, see [CLAUDE.md](CLAUDE.md).

## Advanced Options

### stdio Mode (Local Debugging)

If you need to debug the MCP server in an IDE, use stdio mode:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-env/bin/python",
      "args": ["/path/to/Bridge/scripts/mcp_stdio.py", "--port", "8803"]
    }
  }
}
```

**Note:** `command` should point to the Python interpreter in your virtual environment.

stdio mode runs as a separate process, communicating with Ghidra via HTTP API for easier breakpoint debugging.

## Project Structure

```
Bridge/
├── ghidra_mcp_server.py    # Main server (runs in Ghidra)
├── api/                    # Original API modules
│   ├── search.py
│   ├── view.py
│   ├── rename.py
│   └── ...
├── api_v1/                 # AI-friendly aggregated API
│   ├── search.py
│   ├── view.py
│   ├── list.py
│   └── edit.py
└── scripts/
    ├── mcp_sse_proxy.py    # MCP SSE proxy (subprocess)
    └── mcp_stdio.py        # MCP stdio mode (standalone process)
```

## Troubleshooting

**Server won't start?**
- Confirm a binary file is opened in Ghidra CodeBrowser
- Verify you're using Ghidra 12.0+ (built-in PyGhidra support)

**AI client can't connect?**
- Confirm the server is running (check Ghidra Console output)
- Verify the port number in the configuration file is correct (SSE default: 8804)
- Restart the client (Claude Desktop / Coco / Claude Code)

**API changes not taking effect?**
- Execute hot reload: `curl http://127.0.0.1:8803/_reload`
- Or run `ghidra_mcp_server.py` again in Ghidra

## Development

For detailed API development guide and architecture documentation, see [CLAUDE.md](CLAUDE.md).
