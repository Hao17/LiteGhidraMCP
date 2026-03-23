# Quick Start

## Choosing Your Deployment Mode

| Mode | Best For | AI + GUI | Multi-User |
|------|----------|----------|-----------|
| **Local GUI** | Daily RE work, single user | N/A | No |
| **Docker + Local Project** (`PROJECT_MODE=local`) | Automation only | No (locks project) | No |
| **Docker + Server-Client** ⭐ (`PROJECT_MODE=server`) | Production, collaboration | Yes | Yes |

> **📌 Docker Project Connection Modes**:
>
> This Docker setup supports three project connection methods:
>
> - **Local Project** (`PROJECT_MODE=local`): Mount local .gpr file
>   - ⚠️ **Limitation**: Docker locks the project - **GUI cannot open it while container is running!**
>   - Good for: Pure automation, no GUI interaction
> - **Separated Server-Client** ⭐ **Recommended for AI+GUI** (`PROJECT_MODE=server`): Standalone server + scalable clients
>   - ✅ **AI (Docker) + GUI (human) can work simultaneously!**
>   - ✅ **Multiple clients can connect to shared server**
>   - ✅ **Independent server management - no coupling**
>   - Good for: AI-human collaboration, multiple AI agents, production deployments
>   - See [Separated Server-Client Mode section](#separated-server-client-mode-recommended-for-aigu-collaboration) below
> - **External Ghidra Server** (`PROJECT_MODE=server`): Connect to existing external Server
>   - ✅ **AI (Docker) + GUI (human) can work simultaneously!**
>   - Good for: Production deployments with existing infrastructure
>   - See [README.md - Docker Deployment](../README.md#docker-deployment)

This guide covers all three deployment modes.

### Prerequisites

1. **Docker** and **Docker Compose** installed
2. A **Ghidra project** with at least one binary imported
3. **8GB RAM** recommended (Ghidra is memory-intensive)

### ⚠️ Important Limitation

**This Local Project mode uses Non-Shared Project:**
- When Docker container opens the project, **Ghidra GUI cannot open it simultaneously**
- If you need AI (Docker) + GUI (human) to work together, use **Separated Server-Client mode** above instead

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

## Separated Server-Client Mode (Recommended for AI+GUI Collaboration)

**Best for**: AI + GUI collaboration, multiple AI agents, production deployments

This mode runs a **standalone Ghidra Server** that multiple **Bridge clients** can connect to. The server and clients are completely independent, enabling:
- Multiple AI agents working simultaneously
- Human analysts (Ghidra GUI) + AI collaboration
- Flexible scaling - add/remove clients without affecting the server

### Prerequisites

1. **Docker** and **Docker Compose** installed
2. **8GB RAM** recommended (4GB for Server + 4GB per client)
3. **Data directory** configured in `.env` (default: `~/ghidra-data`)
4. **SSH keys** will be auto-generated on first run

### First-Time Setup

Before starting, configure your data directory:

```bash
cd docker/

# 1. Create environment configuration
cp .env.example .env

# 2. Edit .env and set your data directory
vim .env
# Set: GHIDRA_DATA_DIR=~/ghidra-data (or your preferred location)

# 3. Verify configuration
make info
```

### Quick Start (One Command)

**Start both server and client:**

```bash
cd docker/

# Start everything with one command
make up-separated

# View logs
make logs-separated
```

This starts:
1. **Ghidra Server** on port `13100`
2. **Bridge Client** on ports `8803` (HTTP API) and `8804` (MCP SSE)

### Manual Control (Two Commands)

**For granular control, start server and client separately:**

```bash
cd docker/

# 1. Start server
make server-up

# 2. Start client(s)
make client-up           # First client (8803/8804)
make client2-up          # Second client (8813/8814)
```

### What Gets Created

**Data Structure (Version-Isolated):**
```
${GHIDRA_DATA_DIR}/              # e.g., ~/ghidra-data
├── 12.0.3/                      # Current version directory
│   ├── repos/                   # Server: Project repositories
│   ├── config/                  # Server: Configuration and logs
│   ├── client-config-1/         # Client 1: Cache, preferences, state
│   ├── client-config-2/         # Client 2: Cache, preferences, state
│   └── ssh/
│       └── clients/
│           ├── bridge-1/        # Client 1 SSH keys (auto-generated)
│           │   ├── ssh_key
│           │   └── ssh_key.pub
│           └── bridge-2/        # Client 2 SSH keys (auto-generated)
│               ├── ssh_key
│               └── ssh_key.pub
└── logs/
    └── 12.0.3/
        ├── client-1/            # Client logs
        └── client-2/
```

**What each directory stores:**
- `repos/` - Ghidra Server 项目仓库、用户数据、版本历史
- `config/` - Server 配置文件和日志
- `client-config-N/` - 每个 Client 独立的缓存、偏好设置
- `ssh/clients/` - 每个 Client 的 SSH 密钥对（Client 自动生成，Server 自动注册）

**Server:**
- Port: `13100`
- Repository: `/mcp-projects`
- Users: auto-registered per client (bridge-1, bridge-2, ...)

**Client:**
- HTTP API: `http://localhost:8803`
- MCP SSE: `http://localhost:8804/sse`

### Connect Ghidra GUI

Once the server is running, connect your Ghidra GUI:

1. **Create Shared Project**:
   - File → New Project → **Shared Project**
   - Click "Known Hosts" → "+" to add server

2. **Server Details**:
   - Server Name: `localhost`
   - Port: `13100`

3. **Authentication**:

   - User ID: `root`
   - Use PKI authentication: **✗ Unchecked**
   - Password: (from server logs, see `make server-logs`)

4. **Repository**:
   - Select repository: `/mcp-projects`
   - Click "OK"

5. **Import Binary**:
   - Right-click repository → Import File
   - Select your binary and analyze

### Multiple Clients

**Start second client on different ports:**

```bash
make client2-up  # Ports 8813/8814
```

**Start custom client:**

```bash
CLIENT_ID=3 \
CLIENT_MCP_PORT=8823 \
CLIENT_MCP_SSE_PORT=8824 \
docker-compose -f docker-compose.client.yml up -d
```

### External Server Mode

**To connect client to external Ghidra Server:**

**1. Edit `.env.client`:**
```bash
cp .env.client.example .env.client

# Edit:
GHIDRA_SERVER_HOST=your-server-ip  # or host.docker.internal
GHIDRA_SERVER_PORT=13100
CLIENT_SSH_KEY_PATH=/path/to/keystore
```

**2. Start client:**
```bash
docker-compose -f docker-compose.client.yml --env-file .env.client up -d
```

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
# Server logs
make server-logs

# Client logs
make client-logs

# All logs
make logs-separated
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
make down-separated

# Or stop individually
make server-down
make client-down
```

**Note**: Server data persists in Docker volumes. To remove everything:

```bash
make server-clean  # ⚠️ Destructive - removes all data
```

### User Management

**Default Users:**

| User | Auth Method | Purpose |
|------|-------------|---------|
| `bridge-1` | SSH key (auto-generated) | Docker client 1 (MCP Bridge) |
| `bridge-2` | SSH key (auto-generated) | Docker client 2 (MCP Bridge) |
| `root` | Password (random, shown in logs) | GUI users (Ghidra desktop) |

Each Docker client automatically generates its own SSH key and registers as `bridge-<CLIENT_ID>`.
The `root` password is generated randomly on each server start. Find it in the server logs:

```bash
make server-logs
# Look for:
#   root (password): <random-password>
```

**Connect GUI with root user:**

1. File → New Project → Shared Project
2. Server: `localhost`, Port: `13100`
3. User ID: `root`
4. **Uncheck** "Use PKI authentication"
5. Enter the password from server logs

**Manage Users (via Makefile):**

```bash
# List all users
make server-users

# Add a new user (will prompt for password)
make server-add-user NAME=analyst

# Reset a user's password
make server-reset-password NAME=root

# List repositories and permissions
make server-list-repos
```

**Manage Users (via svrAdmin directly):**

```bash
# Add user
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -add <username> --p

# Remove user
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -remove <username>

# Reset password
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -reset <username> --p

# List users
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -users

# List repositories (with user permissions)
docker exec ghidra-server-standalone /opt/ghidra/server/svrAdmin -list --users
```

### Troubleshooting

**Server won't start:**

```bash
# Check server logs
make server-logs

# Check initialization logs
docker logs ghidra-server-init-standalone

# Verify port is available
lsof -i :13100
```

**Client can't connect to server:**

```bash
# Check server is running
docker ps | grep ghidra-server

# Verify network connectivity
docker exec ghidra-mcp-bridge-client-1 nc -z ghidra-server 13100

# Verify SSH keys were generated
ls -la ~/ghidra-data/12.0.3/ssh/clients/

# Check server registered the user
make server-users

# Check configuration
make info

# Check client logs
make client-logs
```

**GUI connection fails:**

1. Verify server is accessible: `nc -zv localhost 13100`
2. Use `root` user with password from `make server-logs`
3. Ensure "Use PKI authentication" is **unchecked**

**Re-initialize server:**

```bash
# Stop and clean everything
make down-separated
make server-clean

# Start fresh
make up-separated
```

### Advanced: Version Management

**Switch to different Ghidra version:**

```bash
cd docker/

# View current version
make info

# List all versions
make list-versions

# Interactive version switch
make switch-version

# Or manually edit .env
vim .env  # Change GHIDRA_VERSION=12.0.4

# Start with new version
make down-separated
make up-separated
```

**Backup data:**

```bash
# Backup current version
tar czf ghidra-backup-$(date +%Y%m%d).tar.gz ~/ghidra-data/12.0.3

# Backup all versions
tar czf ghidra-all-backup-$(date +%Y%m%d).tar.gz ~/ghidra-data
```

**Custom Configuration (`.env`):**
```bash
# Data storage
GHIDRA_DATA_DIR=~/ghidra-data
GHIDRA_VERSION=12.0.3

# Server settings
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_MAXMEM=8G
SERVER_REPO_NAME=/my-projects
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

**Note:** For Ghidra Server mode setup, see [README.md - Docker Deployment](../README.md#docker-deployment).

## Next Steps

- Read the [API Reference](../CLAUDE.md) for complete API documentation
- Check [Development Guide](../docs/DEVELOPMENT.md) for local development setup
