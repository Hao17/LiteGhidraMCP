# Quick Start

> **📌 Docker Project Connection Modes**:
>
> This Docker setup supports three project connection methods:
>
> - **Local Project** (`PROJECT_MODE=local`): Mount local .gpr file
>   - ⚠️ **Limitation**: Docker locks the project - **GUI cannot open it while container is running!**
>   - Good for: Pure automation, no GUI interaction
> - **Auto-Server** ⭐ **Recommended for AI+GUI** (`PROJECT_MODE=auto-server`): Auto-deploy bundled Ghidra Server
>   - ✅ **AI (Docker) + GUI (human) can work simultaneously!**
>   - ✅ **Zero manual server configuration - one command setup**
>   - Good for: Quick shared project setup, AI-human collaboration
>   - See [Auto-Server Mode section](#auto-server-mode-recommended-for-aigu-collaboration) below
> - **External Ghidra Server** (`PROJECT_MODE=server`): Connect to existing Server
>   - ✅ **AI (Docker) + GUI (human) can work simultaneously!**
>   - Good for: Production deployments with existing infrastructure
>   - See [README.md - Ghidra Server Connection](../README.md#option-2-ghidra-server-connection--production-recommended)

This guide covers all three deployment modes.

### Prerequisites

1. **Docker** and **Docker Compose** installed
2. A **Ghidra project** with at least one binary imported
3. **8GB RAM** recommended (Ghidra is memory-intensive)

### ⚠️ Important Limitation

**This Local Project mode uses Non-Shared Project:**
- When Docker container opens the project, **Ghidra GUI cannot open it simultaneously**
- If you need AI (Docker) + GUI (human) to work together, use **Auto-Server mode** above instead

### Step 1: Prepare Your Ghidra Project

Your Ghidra project directory should have this structure:

```
/path/to/your/ghidra-project/
├── my_binary.gpr          # Project configuration file
└── my_binary.rep/         # Project repository directory
    ├── idata/
    ├── user/
    └── versioned/
```

**Create a project in Ghidra GUI (if you don't have one):**

1. Open Ghidra CodeBrowser
2. Create new project: `File` → `New Project` → `Non-Shared Project`
3. Import binary: `File` → `Import File`
4. Analyze: `Analysis` → `Auto Analyze` (wait for completion)
5. Close Ghidra

### Step 2: Configure Environment

Copy the example environment file:

```bash
cd docker
cp .env.example .env
```

Edit `.env` and update these variables:

```bash
# Path to your Ghidra project on the host
HOST_PROJECT_PATH=/Users/yourname/ghidra-projects/my_binary

# Project name (must match .gpr filename)
PROJECT_NAME=my_binary
```

### Step 3: Build and Start (Local Project Mode)

**Production mode:**

```bash
docker-compose -f docker/docker-compose.yml up -d
```

**Development mode (with code hot-reload):**

```bash
export HOST_PROJECT_PATH=/path/to/your/project
docker-compose -f docker/docker-compose.dev.yml up
```

### Step 4: Verify It's Running

**Check logs:**

```bash
docker-compose -f docker/docker-compose.yml logs -f
```

Look for:
```
==========================================================
  Ghidra MCP Bridge
==========================================================
HTTP API:   http://0.0.0.0:8803
MCP SSE:    http://0.0.0.0:8804/sse
Program:    my_binary (x86/64-bit, 1234 functions)
==========================================================
```

**Test the API:**

```bash
# Health check
curl http://localhost:8803/api/status

# Get program info
curl http://localhost:8803/api/basic_info

# Search functions
curl "http://localhost:8803/api/search/functions?q=main&limit=10"

# Decompile a function
curl "http://localhost:8803/api/view/decompile?name=main"
```

### Step 5: Connect MCP Client

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

Restart Claude Desktop and verify the Ghidra MCP tools appear.

### Coco

Add to your Coco configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

---

## Auto-Server Mode (Recommended for AI+GUI Collaboration)

**Best for**: AI + GUI collaboration without external server setup

This mode automatically deploys a Ghidra Server alongside the Bridge, enabling both the AI (Docker) and human analysts (Ghidra GUI) to work on the same project simultaneously.

### Prerequisites

1. **Docker** and **Docker Compose** installed
2. **8GB RAM** recommended (4GB for Bridge + 4GB for Server)
3. **SSH keys** will be auto-generated in `~/.ghidra/` on first run

### Quick Start

**Option 1: Using Makefile (Recommended)**

```bash
cd docker/

# Start everything with one command
make up-auto-server

# View logs to verify initialization
make logs-auto-server
```

**Option 2: Using docker-compose directly**

```bash
cd docker/

# Optional: Copy pre-configured example
cp .env.auto-server.example .env

# Start services
docker-compose -f docker-compose.yml -f docker-compose.server.yml up -d

# View logs
docker-compose -f docker-compose.yml -f docker-compose.server.yml logs -f
```

### What Gets Created

The auto-server deployment creates:

1. **Ghidra Server** on port `13100`
2. **SSH keys** in `~/.ghidra/bridge_key` (auto-generated if not exists)
3. **Default repository**: `/mcp-projects`
4. **Default user**: `bridge`
5. **Server data** persists in Docker volumes

### Connect Ghidra GUI

Once the server is running, connect your Ghidra GUI:

1. **Create Shared Project**:
   - File → New Project → **Shared Project**
   - Click "Known Hosts" → "+" to add server

2. **Server Details**:
   - Server Name: `localhost`
   - Port: `13100`

3. **Authentication**:
   - User ID: `bridge`
   - Password: (leave empty)
   - Use PKI authentication: **✓ Checked**
   - PKI Keystore: Browse to `~/.ghidra/bridge_key`

4. **Repository**:
   - Select repository: `/mcp-projects`
   - Click "OK"

5. **Import Binary**:
   - Right-click repository → Import File
   - Select your binary and analyze

### Verify It's Working

**Check API:**

```bash
# Health check
curl http://localhost:8803/api/status

# Get program info
curl http://localhost:8803/api/basic_info

# Search functions
curl "http://localhost:8803/api/search/functions?q=main&limit=10"
```

**Check logs:**

```bash
# All services (Bridge + Server)
make logs-auto-server

# Server only
make logs-server

# Bridge only
docker logs ghidra-mcp-bridge -f
```

### Connect MCP Client

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

Restart Claude Desktop - now you can use Ghidra MCP tools while working in the GUI!

### Stop Services

```bash
# Stop everything
make down-auto-server

# Or using docker-compose
docker-compose -f docker-compose.yml -f docker-compose.server.yml down
```

**Note**: Server data persists in Docker volumes. To remove everything:

```bash
docker-compose -f docker-compose.yml -f docker-compose.server.yml down -v
rm -rf ~/.ghidra/bridge_key*  # Remove SSH keys if desired
```

### Troubleshooting Auto-Server

**Server won't start:**

```bash
# Check server logs
docker logs ghidra-server

# Check initialization logs
docker logs ghidra-server-init

# Verify port is available
lsof -i :13100
```

**Bridge can't connect to server:**

```bash
# Check server is running
docker ps | grep ghidra-server

# Verify SSH key permissions
ls -la ~/.ghidra/bridge_key*  # Should be -rw------- (600)

# Check bridge logs
docker logs ghidra-mcp-bridge | grep -i server
```

**GUI connection fails:**

1. Verify server is accessible: `nc -zv localhost 13100`
2. Check SSH key path is correct: `~/.ghidra/bridge_key` (not `.pub`)
3. Ensure "Use PKI authentication" is checked
4. Try manually: `ssh -i ~/.ghidra/bridge_key bridge@localhost -p 13100`

**Re-initialize server:**

```bash
# Stop everything
make down-auto-server

# Remove volumes
docker volume rm ghidra-server-repos ghidra-server-config

# Remove SSH keys
rm -rf ~/.ghidra/bridge_key*

# Start fresh
make up-auto-server
```

---

## Local Project Mode (Automation Only)

This section covers **local project mode** for pure automation (no GUI collaboration).

⚠️ **Limitation**: When Docker container opens the project, Ghidra GUI cannot open it simultaneously. Use Auto-Server mode above for AI+GUI collaboration.

## Common Operations

### Hot Reload API Modules

After editing code in `api/` or `api_v1/`:

```bash
curl http://localhost:8803/_reload
```

### Stop the Service

```bash
docker-compose -f docker/docker-compose.yml down
```

### View Container Logs

```bash
docker logs ghidra-mcp-bridge -f
```

### Access Container Shell

```bash
docker exec -it ghidra-mcp-bridge /bin/bash
```

### Check Health Status

```bash
docker inspect ghidra-mcp-bridge | grep Health -A 10
```

## Troubleshooting

### Container Exits Immediately

**Check logs:**
```bash
docker logs ghidra-mcp-bridge
```

**Common causes:**
1. Project path not mounted correctly
2. Project name doesn't match `.gpr` file
3. Not enough memory (increase Docker memory limit)

### API Not Responding

**Check if service is running:**
```bash
docker ps | grep ghidra
```

**Check health:**
```bash
curl -v http://localhost:8803/api/status
```

### Initialization Failed

**Error:** `Failed to start JVM` or `Ghidra not found`

**Solution:** The Dockerfile downloads Ghidra automatically. If it fails, check:
1. Network connectivity
2. Ghidra download URL is correct (see Dockerfile)

### Project Not Found

**Error:** `Project file not found: /ghidra-projects/my_binary.gpr`

**Solution:**
1. Check `HOST_PROJECT_PATH` in `.env`
2. Verify `PROJECT_NAME` matches `.gpr` filename
3. Ensure volume is mounted: `docker inspect ghidra-mcp-bridge | grep Mounts -A 20`

### Out of Memory

**Symptoms:** Container killed or frozen

**Solution:** Increase Docker memory limit:

```yaml
# In docker-compose.yml
deploy:
  resources:
    limits:
      memory: 12G  # Increase this
```

## Performance Tips

### 1. Use SSD for Project Storage

Mount your Ghidra project on an SSD for better performance.

### 2. Pre-Analyze Binaries

Analyze binaries in Ghidra GUI before starting the Docker container:
- Faster API responses
- No analysis delays on first request

### 3. Limit Resource Usage

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'      # Match your system
      memory: 8G       # Adjust based on binary size
```

## Advanced Usage

### Multi-Binary Project

If your project has multiple binaries, specify which one to load via environment variable:

```bash
# TODO: Not yet implemented
# Will be added in future update
```

### Ghidra Server Mode

```bash
# In .env
PROJECT_MODE=server
GHIDRA_SERVER_HOST=ghidra-server.local
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=analyst
GHIDRA_SERVER_REPO=/shared
```

**Note:** For Ghidra Server mode setup, see [README.md - Ghidra Server Connection](../README.md#option-2-ghidra-server-connection--production-recommended).

## Next Steps

- Read the [API Reference](../docs/api/api-reference.md)
- Explore [MCP Tools](../docs/setup/mcp-clients.md)
- Check [Development Guide](../docs/development/contributing.md)
