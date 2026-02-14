# Ghidra MCP Bridge

English | [简体中文](README_ZH.md)

> **Version Notice**:
> - **Current branch (main)**: Ghidra 12.0+ / PyGhidra version
> - **Ghidra 11.x users**: Please switch to [`ghidra-11-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/tree/ghidra-11-ghidrathon) branch or use [`v1.0-ghidrathon`](https://github.com/Hao17/LiteGhidraMCP/releases/tag/v1.0-ghidrathon) tag

A PyGhidra-based MCP (Model Context Protocol) Bridge that runs inside Ghidra 12.0+, providing AI systems with programmatic access to Ghidra's reverse engineering capabilities.

## Quick Start Guide

**For most users: Start with GUI Mode**
- → [Run MCP in Ghidra GUI](#quick-start): Simplest setup, run script directly in Ghidra
- No Docker, no complex configuration needed
- Best for learning and daily analysis work

**For professional reverse engineers:**

If you need production-grade deployment or team collaboration, see [Docker Deployment](#docker-deployment) section for:
- Containerized deployment options
- Local Project mode (automation only)
- Ghidra Server mode (AI + GUI collaboration)

---

## Quick Start

**Requirements:**
- Ghidra 12.0+ (download: https://ghidra-sre.org/)
- Python dependencies: `pip install -r requirements.txt`

> **Note**: Uses Ghidra 12.0+'s built-in PyGhidra. Docker mode doesn't need local installation - everything is included in the container.

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

### 2. Available Tools

Once configured, your AI client will automatically gain access to the following Ghidra tools:

- **ghidra_search**: Search functions, symbols, strings, cross-references, etc.
- **ghidra_view**: Decompilation/disassembly viewing
- **ghidra_list**: Symbol list browsing (similar to ls)
- **ghidra_edit**: Unified editing (rename, datatype setting, comments)
- **ghidra_basic_info**: Get basic program information

### 3. Configure AI Client

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

## Docker Deployment

Docker mode runs Ghidra headless + MCP Bridge in a container, based on Ghidra 12.0+ with PyGhidra.

### Deployment Options Comparison

| Feature | Local GUI | Docker + Local Project | Docker + Ghidra Server |
|---------|-----------|------------------------|------------------------|
| **Use Case** | Daily analysis | Automation only | Production/Collaboration |
| **Deployment** | Ghidra GUI | Docker container | Docker container |
| **Ghidra Source** | Local installation | Containerized | Containerized |
| **Project Source** | GUI-opened | Volume mount (.gpr) | Ghidra Server |
| **AI + GUI Simultaneously** | N/A | **No - GUI locked** | **Yes - Full collaboration** |
| **Persistence** | Session-based | Volume mount | Server storage |
| **Concurrent Access** | Single user | Locked by container | Multi-user safe |
| **Version Control** | No | No | Built-in |
| **User Isolation** | No | No | Separate sessions |
| **Container Restart** | N/A | Remount needed | Auto recovery |

> **Important Limitation**:
> - **Local Project mode** uses Non-Shared Project - Docker container **locks** the project, **GUI cannot open it simultaneously**
> - **Server mode** uses Shared Project - Docker (AI analyst) and GUI (human analyst) can work **together in parallel**

### Choose Your Deployment Scenario

**Currently available modes** (configured via `PROJECT_MODE` environment variable):

1. **Local Project** (`PROJECT_MODE=local`): Mount local .gpr file
   - Good for: Pure automation, no GUI interaction needed
   - Limitation: Docker locks the project, GUI cannot open it simultaneously

2. **Ghidra Server** (`PROJECT_MODE=server`): Connect to Ghidra Server (recommended for production)
   - Good for: AI + human collaboration, team work, production deployment
   - Advantage: AI and GUI can work together, persistent storage, version control

**Future planned mode** (not yet implemented):

3. **Local Ghidra Instance** (`PROJECT_MODE=host-ghidra`): Use host's Ghidra installation
   - Will enable: Access to your existing plugins and scripts
   - Status: Not yet implemented

---

### Option 1: Local Project Connection (Automation Only)

**CRITICAL LIMITATION**: Non-Shared Project - **Docker locks the project, GUI cannot open it simultaneously!**

- Good for: Pure automation, no GUI interaction needed
- Not suitable for: AI-human collaboration, manual review

**Configuration:** Set `PROJECT_MODE=local` in `.env`

**1. Prepare Ghidra Project**

Create and analyze a project in Ghidra GUI (first-time setup):

```bash
# Example project directory structure
/path/to/ghidra-projects/my_binary/
├── my_binary.gpr          # Project configuration file
└── my_binary.rep/         # Project repository directory
```

**2. Build PyGhidra Image**

```bash
docker build -f docker/Dockerfile.pyghidra -t ghidra-bridge:pyghidra .
```

**3. Configure Environment**

```bash
cd docker
cp .env.example .env
# Edit .env to set HOST_PROJECT_PATH and PROJECT_NAME
```

`.env` example:

```bash
# Host Ghidra project path
HOST_PROJECT_PATH=/Users/username/ghidra-projects/my_binary

# Project name (must match .gpr filename)
PROJECT_NAME=my_binary

# Port configuration
GHIDRA_MCP_PORT=8803
GHIDRA_MCP_SSE_PORT=8804
```

**4. Start Service**

```bash
docker-compose -f docker/docker-compose.pyghidra.yml up -d
```

**5. Verify Deployment**

```bash
# View logs
docker logs -f ghidra-mcp-bridge-pyghidra

# Test API
curl http://localhost:8803/api/basic_info
curl "http://localhost:8803/api/search/functions?q=main"

# Test MCP
curl http://localhost:8804/sse
```

**6. Configure AI Client**

Same as local mode, connect to `http://localhost:8804/sse`.

**Detailed documentation**: [docker/QUICKSTART.pyghidra.md](docker/QUICKSTART.pyghidra.md)

---

### Option 2: Ghidra Server Connection - Production Recommended

**The ONLY way to use AI (Docker) + GUI (Human) simultaneously!**

**Configuration:** Set `PROJECT_MODE=server` in `.env` + configure Server connection variables

**Why connect to Ghidra Server?**

Using Ghidra Server (Shared Project) provides professional collaboration architecture:

**vs. Local Project**:
- **Docker and GUI can work together** (Local Project locks the file)
- **Persistent storage** (data survives container deletion)
- **Version control** (built-in conflict resolution)
- **Multi-user safe** (AI analyst + human analyst as separate users)

**Additional benefits**:
- **Permission isolation**: Track who made what changes (AI vs human)
- **Concurrent safety**: Multiple AI agents + human analysts can work in parallel
- **Container restart safe**: All data in Server, container is just a client

#### Standard Collaboration Architecture

In this architecture, Ghidra Server is the **central coordinator**, while MCP Bridge and GUI are **equal client users**:

```
┌─────────────────────────────────────────────────┐
│           Ghidra Server (Docker)                │
│                                                 │
│  Repository: /repos/my_project                  │
│  - Persistent storage (Volume mounted)          │
│  - Version control and conflict management      │
│  - User permission management                   │
└────────┬──────────────────────┬─────────────────┘
         │                      │
         │ User: "ai_analyst"   │ User: "human_analyst"
         │ (AI Analyst)         │ (Human Analyst)
         v                      v
┌────────────────────┐  ┌──────────────────────┐
│  MCP Bridge        │  │  Ghidra GUI          │
│  (Docker)          │  │  (Local/Remote)      │
│                    │  │                      │
│  - AI-driven       │  │  - Interactive       │
│    analysis        │  │    reverse           │
│  - Auto rename     │  │  - Manual review     │
│  - Batch process   │  │  - Visual debug      │
│                    │  │                      │
│  HTTP API :8803    │  │                      │
│  MCP SSE  :8804    │  │                      │
└────────────────────┘  └──────────────────────┘
         │                      │
         v                      v
   AI Client              Analyst Workstation
  (Claude Desktop)       (Interactive operation)
```

**Workflow**:
1. **Ghidra Server** manages shared repository `/repos/my_project`
2. **MCP Bridge User** (`ai_analyst`) - AI-driven automated analysis
   - Execute batch renaming and type inference via MCP tools
   - Auto-annotate functions, variables, data structures
   - Respond to AI client analysis requests
3. **GUI User** (`human_analyst`) - Human analyst
   - Review AI analysis results
   - Manual debugging and deep analysis
   - Visualize cross-references and control flow
4. **Bidirectional sync** - Both users' modifications synchronized in real-time via Server

**Advantages**:
- AI and human analysts can **work in parallel** without interference
- Server automatically handles **version conflicts** (e.g., both modifying the same function)
- **Responsibility separation**: Track which modifications came from AI vs human
- **Container restart doesn't lose data**: All state saved in Server persistent storage

#### Deployment Steps

**1. Generate SSH Keys (for Server authentication)**

Generate keys for AI analyst (MCP Bridge) and human analyst separately:

```bash
mkdir -p ~/.ghidra

# AI analyst key (used by MCP Bridge)
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/ai_analyst_key -N ""

# Human analyst key (used by GUI)
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/human_analyst_key -N ""
```

**2. Deploy Ghidra Server + Bridge**

Add Ghidra Server to your Docker Compose configuration, and configure Bridge with `PROJECT_MODE=server`:

```yaml
version: '3.8'

services:
  # Ghidra Server - Central coordinator for multi-user collaboration
  ghidra-server:
    image: blacktop/ghidra:12.0-server
    container_name: ghidra-server
    ports:
      - "13100-13102:13100-13102"
    volumes:
      - ./ghidra-repos:/repos:rw           # Repository persistence
      - ./ghidra-config:/ghidra/.ghidraServer:rw  # Config persistence
    environment:
      - MAXMEM=4G
      - GHIDRA_USERS=ai_analyst human_analyst  # Two independent users
    restart: unless-stopped

  # MCP Bridge - Connects to Server as "ai_analyst" user
  ghidra-bridge:
    image: ghidra-bridge:pyghidra
    depends_on:
      - ghidra-server
    environment:
      # !!! Key setting: Use server mode !!!
      - PROJECT_MODE=server
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_PORT=13100
      - GHIDRA_SERVER_USER=ai_analyst        # AI analyst user
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
      - GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
    volumes:
      - ~/.ghidra/ai_analyst_key:/root/.ghidra/ssh_key:ro  # AI analyst key
      - ./logs:/app/logs:rw
    ports:
      - "8803:8803"
      - "8804:8804"
    restart: unless-stopped
```

> **Note**: This uses the same Bridge image, just configured with `PROJECT_MODE=server` instead of `PROJECT_MODE=local`

**3. Configure Ghidra Server Users (after first startup)**

```bash
# Start Server
docker-compose up -d ghidra-server

# Enter Server container
docker exec -it ghidra-server /bin/bash

# Add AI analyst user
ghidra-server-admin add-user ai_analyst
# Add ~/.ghidra/ai_analyst_key.pub content to authorized_keys

# Add human analyst user
ghidra-server-admin add-user human_analyst
# Add ~/.ghidra/human_analyst_key.pub content to authorized_keys

# Create shared repository
ghidra-server-admin create-repository /shared

# Grant access to both users
ghidra-server-admin grant-access /shared ai_analyst
ghidra-server-admin grant-access /shared human_analyst

exit
```

**4. Start MCP Bridge Service**

```bash
# Start Bridge (AI analyst)
docker-compose up -d ghidra-bridge

# View logs
docker logs -f ghidra-bridge
```

**5. Configure GUI User (Human Analyst) to Connect to Server**

Configure Ghidra GUI on analyst's workstation:

```bash
# 1. In Ghidra GUI: Create Server connection
# File → New Project → Shared Project

# 2. Configure Server connection info:
Server Name:    ghidra-server  (or localhost:13100)
Port Number:    13100
User ID:        human_analyst
Repository:     /shared
Project Name:   my_project

# 3. Configure SSH authentication
# Add ~/.ghidra/human_analyst_key to Ghidra's SSH settings
```

**6. Verify Dual-User Collaboration**

```bash
# Test AI analyst (MCP Bridge)
curl http://localhost:8803/api/basic_info
# Should show project info connected to Server, User: ai_analyst

# Test human analyst in GUI
# Open Ghidra GUI → Connect to Server → Open my_project
# Status bar should show: Connected as human_analyst

# Test collaboration: Rename a function in GUI
# Check in MCP: curl "http://localhost:8803/api/search/functions?q=new_name"
# Should see GUI's modification

# Test reverse: Rename function via MCP
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "ai_renamed_func"}'

# Refresh in GUI, should see AI's modification
```

#### Data Persistence Verification

**Key advantage**: In Server mode, even if all containers (including Bridge and Server) are deleted, data is fully retained.

```bash
# 1. Make some modifications via MCP
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "comment.set", "name": "main", "type": "PLATE", "text": "AI analyzed"}'

# 2. Stop and delete all containers
docker-compose down

# 3. Verify data persistence
ls -la ./ghidra-repos/shared/
# Should see complete repository structure

# 4. Restart (data auto-recovers)
docker-compose up -d

# 5. Verify modification still exists
curl "http://localhost:8803/api/v1/view?q=main&type=decompile"
# Should see previously added comment "AI analyzed"

# 6. GUI user reconnects
# Ghidra GUI → Connect to Server → Open project
# All history modifications (AI + human) fully retained
```

**Persistent storage explanation**:
- **Repository data**: `./ghidra-repos/` → Server container's `/repos`
- **Server config**: `./ghidra-config/` → Server container's `/.ghidraServer`
- **Bridge logs**: `./logs/` → Bridge container's `/app/logs`

Deleting containers only removes runtime state; all analysis data is saved in host volumes.

#### Multi-AI Agent Collaboration (Advanced Scenario)

You can deploy multiple MCP Bridge instances, each as an independent AI analyst, working collaboratively:

```yaml
services:
  ghidra-server:
    # ... (same as above)
    environment:
      - GHIDRA_USERS=ai_code_analyst ai_vuln_analyst human_analyst

  # AI Agent 1: Code analysis expert
  bridge-code-analyst:
    image: ghidra-bridge:pyghidra
    container_name: bridge-code-analyst
    environment:
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_USER=ai_code_analyst
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
    volumes:
      - ~/.ghidra/ai_code_analyst_key:/root/.ghidra/ssh_key:ro
    ports:
      - "8803:8803"  # MCP for code analysis
      - "8804:8804"

  # AI Agent 2: Vulnerability analysis expert
  bridge-vuln-analyst:
    image: ghidra-bridge:pyghidra
    container_name: bridge-vuln-analyst
    environment:
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_USER=ai_vuln_analyst
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
    volumes:
      - ~/.ghidra/ai_vuln_analyst_key:/root/.ghidra/ssh_key:ro
    ports:
      - "8805:8803"  # MCP for vulnerability analysis
      - "8806:8804"
```

**Use case**:
- `ai_code_analyst`: Focus on function identification, renaming, type inference
- `ai_vuln_analyst`: Focus on vulnerability pattern search, dangerous function annotation
- `human_analyst`: Review AI results, deep analysis of key logic

**Claude Desktop configuration (multi-agent)**:
```json
{
  "mcpServers": {
    "ghidra-code": {
      "url": "http://localhost:8804/sse"
    },
    "ghidra-vuln": {
      "url": "http://localhost:8806/sse"
    }
  }
}
```

All agents' modifications are synchronized via Server and can be viewed uniformly in GUI.

**Detailed configuration**: See [`examples/docker/ghidra-server/docker-compose.pyghidra.yml`](examples/docker/ghidra-server/docker-compose.pyghidra.yml)

## Advanced Options

### HTTP API

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

# Shutdown server
curl http://127.0.0.1:8803/_shutdown
```

For complete API documentation, see [CLAUDE.md](CLAUDE.md).

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

### Environment Variables

Customize server ports via environment variables (optional):

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

Then configure multiple MCP servers in your AI client (see Claude Desktop multi-program configuration example above).

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

## Development

For detailed API development guide and architecture documentation, see [CLAUDE.md](CLAUDE.md).
