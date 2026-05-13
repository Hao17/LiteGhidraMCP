# Quick Start

## Choosing Your Deployment Mode

| Mode | Best For | AI + GUI | Multi-User |
|------|----------|----------|-----------|
| **Local GUI** | Daily RE work, single user | N/A | No |
| **Docker + Local Project** (`PROJECT_MODE=local`) | Automation only | No (locks project) | No |
| **Docker + Server-Client** ⭐ (`PROJECT_MODE=server`) | Production, collaboration | Yes | Yes |

### Prerequisites

1. **Docker** and **Docker Compose** installed
2. **8GB RAM** recommended (Ghidra is memory-intensive)
3. **gmcp CLI** installed: `pip install -e .` (from project root)

---

## Separated Server-Client Mode ⭐ Recommended

AI (Docker) + GUI (Human) collaboration. Each client binds to one REPO/BINARY at startup.

### Start Server

```bash
gmcp server up
```

On first run this will:
1. Auto-create `docker/.env` with defaults (`GHIDRA_DATA_DIR=~/ghidra-data`)
2. Start the Ghidra Server on port `13100`
3. **Prompt you to register an admin user** (username + password) for GUI access

All future repositories will auto-grant access to this admin user.

### Start Client

```bash
# --repo required, --binary recommended
gmcp client start 1 --repo test --binary my_binary                          # Open existing binary
gmcp client start 1 --repo test --binary 38.1.0/my_binary                  # By repo path
gmcp client start 1 --repo test --binary my_binary --binary-file ~/a.bin   # Import + open

# Second client on different ports (8813/8814)
gmcp client start 2 --repo test --binary modules/other_binary

# Or start server + client 1 in one command
gmcp up --repo test --binary my_binary
```

### What Gets Created

**Services:**
- Ghidra Server: port `13100`
- HTTP API: `http://localhost:8803`
- MCP SSE: `http://localhost:8804/sse`
- Each client auto-generates SSH key and registers as `bridge-<N>`

**Data Structure (Version-Isolated):**
```
~/ghidra-data/                       # GHIDRA_DATA_DIR
└── 12.0.3/                          # Version directory
    ├── repos/                       # Server project repositories
    ├── config/                      # Server config (+ .admin_user marker)
    ├── client-config-1/             # Client 1 cache, preferences
    ├── client-config-2/             # Client 2 cache, preferences
    ├── imports/                     # Staged binary files for import
    └── ssh/clients/
        ├── bridge-1/               # Client 1 SSH keys (auto-generated)
        │   ├── ssh_key
        │   └── ssh_key.pub
        └── bridge-2/               # Client 2 SSH keys
```

### Connect Ghidra GUI

1. File → New Project → **Shared Project**
2. Server: `localhost:13100`
3. User: the admin username you registered, **uncheck** "Use PKI authentication"
4. Password: the one you set during registration
5. Select a repository

> For `root` user, find the random password via `gmcp server logs` (look for `root (password): ...`)

### Useful Commands

```bash
# Server
gmcp server up             # Start server
gmcp server down           # Stop server
gmcp server logs           # View server logs
gmcp server users          # List registered users
gmcp server add-user x     # Add another user (prompts for password)
gmcp server repos          # List repositories and permissions
gmcp server clean          # Remove all data (destructive, re-prompts admin on next start)

# Client
gmcp client start N --repo <name> [--binary <name>] [--binary-file <path>]
gmcp client stop N         # Stop client N
gmcp client logs N         # View client N logs
gmcp client list           # List all running clients

# Stack
gmcp up --repo <name>      # Start server + client 1
gmcp down                  # Stop everything

# Info & Debug
gmcp info                  # Show current configuration
gmcp troubleshoot check    # Diagnose problems
gmcp troubleshoot fix      # Auto-fix detected problems
```

**Makefile alternative** (from `docker/` directory):

```bash
make server-up             # Same as gmcp server up (also prompts admin on first run)
make client N=1 REPO=test BINARY=my_binary
make client-stop N=1
make client-list
make down-separated
```

### Connect MCP Client

```bash
# Quick setup via gmcp
gmcp install mcp claude-code        # Claude Code
gmcp install mcp claude-desktop     # Claude Desktop
gmcp install mcp coco               # Coco

# Multi-client (auto-calculates port)
gmcp install mcp claude-code --client 2   # → ghidra-2 on port 8814
```

**Manual configuration** — see [README.md](../README.md#configure-ai-client).

### Port Calculation

| Client N | HTTP API | MCP SSE |
|----------|----------|---------|
| 1 | 8803 | 8804 |
| 2 | 8813 | 8814 |
| 3 | 8823 | 8824 |
| N | 8800+(N-1)*10+3 | 8800+(N-1)*10+4 |

### User Management

**Default Users:**

| User | Auth | Purpose |
|------|------|---------|
| Admin (you set) | Password | GUI access, auto-granted to all repos |
| `root` | Password (random per restart) | Fallback GUI access |
| `bridge-N` | SSH key (auto-generated) | Docker client N |

```bash
gmcp server users                # List all users
gmcp server add-user analyst     # Add user (prompts for password)
gmcp server reset-password root  # Reset password
gmcp server repos                # List repos with permissions
```

### Verify It's Working

```bash
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
curl "http://localhost:8803/api/search/functions?q=main&limit=10"
```

---

## Local Project Mode (Automation Only)

Mount a local `.gpr` project into Docker. **GUI cannot open it simultaneously.**

### Setup

```bash
cd docker && cp .env.example .env
```

Edit `.env`:
```bash
HOST_PROJECT_PATH=/path/to/your/ghidra-project
PROJECT_NAME=my_binary
PROJECT_MODE=local
```

### Start

```bash
docker-compose up -d
```

### Verify

```bash
docker-compose logs -f
curl http://localhost:8803/api/status
```

---

## External Ghidra Server

Connect to an existing Ghidra Server with `PROJECT_MODE=server`. Edit `.env`:

```bash
PROJECT_MODE=server
GHIDRA_SERVER_HOST=192.168.1.100
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=my_user
GHIDRA_SERVER_REPO=/my_repo
GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
```

---

## Common Operations

### Hot Reload API Modules

```bash
curl http://localhost:8803/_reload
```

### Version Management

```bash
gmcp info                # Current version and data paths
gmcp versions            # List all versions
gmcp switch-version      # Interactive version switch
```

---

## Troubleshooting

**Server won't start:**
```bash
gmcp server logs         # Check server logs
lsof -i :13100           # Verify port is available
```

**Client can't connect to server:**
```bash
gmcp client logs 1                   # Check client logs
gmcp server users                    # Verify user registration
gmcp troubleshoot check              # Run diagnostics
```

**GUI connection fails:**
1. Verify server: `nc -zv localhost 13100`
2. Use admin user or `root` (password from `gmcp server logs`)
3. **Uncheck** "Use PKI authentication"

**Re-initialize:**
```bash
gmcp down                # Stop everything
gmcp server clean        # Remove all data
gmcp server up           # Fresh start (re-prompts admin registration)
```

---

## Advanced

### Custom Configuration

Override defaults by editing `docker/.env`:

```bash
GHIDRA_DATA_DIR=~/ghidra-data     # Data storage root
GHIDRA_VERSION=12.0.3             # Ghidra version
GHIDRA_SERVER_PORT=13100          # Server port
GHIDRA_SERVER_MAXMEM=8G          # Server memory
SERVER_REPO_NAME=/my-projects     # Default repo name
```

### Performance Tips

- Use SSD for `GHIDRA_DATA_DIR`
- Pre-analyze binaries in Ghidra GUI before AI analysis
- Increase `GHIDRA_SERVER_MAXMEM` for large binaries

## Next Steps

- [API Reference](../CLAUDE.md) — Complete API documentation
- [SKILL.md](../docs/SKILL.md) — AI analysis workflows and MCP tool usage
- [ARCHITECTURE.md](ARCHITECTURE.md) — Docker architecture details
