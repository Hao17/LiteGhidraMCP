# Quick Start

> **📌 Docker Project Connection Modes**:
>
> This Docker setup supports two project connection methods (same deployment, different config):
>
> - **Local Project** (`PROJECT_MODE=local`, this guide): Mount local .gpr file
>   - ⚠️ **Limitation**: Docker locks the project - **GUI cannot open it while container is running!**
>   - Good for: Pure automation, no GUI interaction
> - **Ghidra Server** ⭐ **Production recommended** (`PROJECT_MODE=server`): Connect to Server
>   - ✅ **AI (Docker) + GUI (human) can work simultaneously!**
>   - Good for: AI-human collaboration, persistent storage, version control
>   - See [README.md - Ghidra Server Connection](../README.md#option-2-ghidra-server-connection--production-recommended)
>   - Example: [`examples/docker/ghidra-server/docker-compose.yml`](../examples/docker/ghidra-server/docker-compose.yml)

This guide shows how to quickly deploy Ghidra MCP Bridge with **local project connection** for automation testing.

## Prerequisites

1. **Docker** and **Docker Compose** installed
2. A **Ghidra project** with at least one binary imported
3. **8GB RAM** recommended (Ghidra is memory-intensive)

## ⚠️ Important Limitation

**This Local Project mode uses Non-Shared Project:**
- When Docker container opens the project, **Ghidra GUI cannot open it simultaneously**
- If you need AI (Docker) + GUI (human) to work together, use **Ghidra Server mode** instead
- See [README.md - Ghidra Server Connection](../README.md#option-2-ghidra-server-connection--production-recommended)

## Step 1: Prepare Your Ghidra Project

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

## Step 2: Configure Environment

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

## Step 3: Build and Start

**Production mode:**

```bash
docker-compose -f docker/docker-compose.yml up -d
```

**Development mode (with code hot-reload):**

```bash
export HOST_PROJECT_PATH=/path/to/your/project
docker-compose -f docker/docker-compose.dev.yml up
```

## Step 4: Verify It's Running

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

## Step 5: Connect MCP Client

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
