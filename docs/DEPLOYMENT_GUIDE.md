# Deployment Guide

A comprehensive guide to deploying Ghidra MCP Bridge across different environments and use cases.

## Table of Contents

- [Choosing the Right Deployment Mode](#choosing-the-right-deployment-mode)
- [Decision Flowchart](#decision-flowchart)
- [Local GUI Mode](#local-gui-mode)
- [Docker Mode](#docker-mode)
  - [Docker + Local Project](#docker--local-project)
  - [Docker + Ghidra Server](#docker--ghidra-server)
- [Migration Paths](#migration-paths)
- [Production Best Practices](#production-best-practices)

---

## Choosing the Right Deployment Mode

Ghidra MCP Bridge supports two deployment modes:

| Mode | Best For | Key Features | Limitations |
|------|----------|--------------|-------------|
| **Local GUI** | Daily reverse engineering | Interactive GUI, hot reload | Session-based, single user |
| **Docker** ⭐ | Production, automation | Containerized, can connect to local or Server | Requires Docker setup |

### Docker Project Connection Options

Docker mode can connect to projects in two ways (same deployment, different config):

| Connection | Configuration | Best For | AI + GUI Simultaneously | Multi-User |
|------------|---------------|----------|------------------------|-----------|
| **Local Project** | `PROJECT_MODE=local` | Automation only | ❌ **Locks project** | ❌ No |
| **Ghidra Server** ⭐ | `PROJECT_MODE=server` | Production, collaboration | ✅ **Works together** | ✅ Yes |

> **⚠️ Critical**: Local Project uses Non-Shared Project - when Docker opens it, GUI **cannot** open it simultaneously!

### Quick Recommendations

**Choose Local GUI Mode if:**
- You're a reverse engineer doing daily analysis work
- You want to use Ghidra GUI interactively
- You're testing the MCP Bridge for the first time
- You need quick hot-reload for development

**Choose Docker + Local Project if:**
- You want containerized deployment for testing
- You're running **pure automation** (no GUI needed)
- You need reproducible environments
- ⚠️ **You accept that GUI cannot be used while container is running**

**Choose Docker + Ghidra Server if:** ⭐ **Production Recommended**
- You need **AI (Docker) and GUI (human) to work simultaneously**
- You're deploying for production use
- You want persistent storage across container restarts
- You need version control and conflict resolution
- Multiple AI agents will work on the same project
- You want to track who made which modifications

**TIP**: Use `make up-with-server` for **auto-deployment** - server setup happens automatically!

---

## Decision Flowchart

```
Start: Need to deploy Ghidra MCP Bridge
│
├─ Q: Is this for production use?
│  │
│  ├─ Yes → ✅ Docker Mode
│  │        │
│  │        └─ Q: Do you need multi-user collaboration?
│  │             │
│  │             ├─ Yes → Configure: PROJECT_MODE=server ⭐ (Ghidra Server)
│  │             │
│  │             └─ No → Q: Do you need data persistence across container restarts?
│  │                      │
│  │                      ├─ Yes → Configure: PROJECT_MODE=server ⭐ (Server for durability)
│  │                      │
│  │                      └─ No → Configure: PROJECT_MODE=local (Simple mount)
│  │
│  └─ No → Q: Do you want containerized deployment?
│           │
│           ├─ Yes → Docker Mode
│           │        │
│           │        └─ Q: Is this for development/testing?
│           │             │
│           │             ├─ Yes → Configure: PROJECT_MODE=local (Quick testing)
│           │             │
│           │             └─ No → Configure: PROJECT_MODE=server (Learn production setup)
│           │
│           └─ No → Q: Do you use Ghidra GUI daily?
│                    │
│                    ├─ Yes → Local GUI Mode
│                    │
│                    └─ No → Consider Docker Mode for automation
```

**Key Point**: Docker mode is a single deployment - choose `PROJECT_MODE=local` or `PROJECT_MODE=server` in `.env`

---

## Local GUI Mode

### Overview

Run MCP Bridge as a Python script inside Ghidra CodeBrowser GUI. Best for interactive reverse engineering work.

### Architecture

```
┌─────────────────────────────────────┐
│  Ghidra CodeBrowser (GUI)           │
│  ├─ Binary loaded in GUI            │
│  ├─ ghidra_mcp_server.py (script)   │
│  ├─ HTTP API :8803                  │
│  └─ MCP SSE  :8804 (subprocess)     │
└─────────────────────────────────────┘
         │
         v
   AI Client (Claude Desktop)
```

### Prerequisites

- Ghidra 12.0+ installed
- Binary opened in Ghidra CodeBrowser
- Python dependencies (for MCP): `pip install -r requirements.txt`

### Setup Steps

1. **Add script path to Ghidra**:
   - Open Script Manager (`Window` → `Script Manager`)
   - Click "Manage Script Directories" (folder icon)
   - Add project root directory

2. **Run server script**:
   - Locate `ghidra_mcp_server.py` in Script Manager
   - Execute script
   - Confirm log shows:
     ```
     Server started on http://127.0.0.1:8803
     MCP SSE server started on http://127.0.0.1:8804
     ```

3. **Configure AI client**:
   - Claude Desktop: Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Add:
     ```json
     {
       "mcpServers": {
         "ghidra": {
           "url": "http://127.0.0.1:8804/sse"
         }
       }
     }
     ```

### Advantages

- ✅ Interactive with Ghidra GUI
- ✅ Hot reload support (re-run script)
- ✅ Easy debugging in GUI console
- ✅ No Docker required

### Limitations

- ❌ Session-based (stops when GUI closes)
- ❌ Single user only
- ❌ No version control
- ❌ Not suitable for automation

### Use Cases

- Daily reverse engineering with AI assistance
- Quick analysis of single binaries
- Development and testing of API changes
- Learning how the Bridge works

---

## Docker Mode

### Overview

Run Ghidra headless + MCP Bridge in a Docker container. Supports two project connection methods:

- **Local Project** (`PROJECT_MODE=local`): Mount .gpr file from host
- **Ghidra Server** (`PROJECT_MODE=server`): Connect to Ghidra Server

**Key Point**: Same Docker setup (`docker-compose.pyghidra.yml`), different `.env` configuration!

---

### Docker + Local Project

**⚠️ CRITICAL LIMITATION**: Non-Shared Project - **Docker locks the project, GUI cannot open it simultaneously!**

**Configuration**: `PROJECT_MODE=local` in `.env`

**Good for**: Pure automation, no GUI interaction
**Not suitable for**: AI-human collaboration, manual review

#### Architecture

```
┌─────────────────────────────┐
│  Host: Ghidra Project       │
│  /path/to/my_binary/        │
│  ├── my_binary.gpr          │
│  └── my_binary.rep/         │
└──────────┬──────────────────┘
           │ bind mount
┌──────────v──────────────────┐
│  Docker Container           │
│  - Ghidra 12.0 + PyGhidra   │
│  - MCP Bridge               │
│  - HTTP API :8803           │
│  - MCP SSE  :8804           │
│  - PROJECT_MODE=local       │
└─────────────────────────────┘
         │
         v
   AI Client (Claude Desktop)
```

### Prerequisites

- Docker and Docker Compose installed
- Ghidra project created (use GUI to create and analyze)
- 8GB RAM recommended

### Setup Steps

1. **Prepare Ghidra project**:
   ```bash
   # Create project in Ghidra GUI first
   # Structure should be:
   # /path/to/my_binary/
   # ├── my_binary.gpr
   # └── my_binary.rep/
   ```

2. **Build Docker image**:
   ```bash
   docker build -f docker/Dockerfile.pyghidra -t ghidra-bridge:pyghidra .
   ```

3. **Configure environment**:
   ```bash
   cd docker
   cp .env.example .env
   # Edit .env:
   # HOST_PROJECT_PATH=/path/to/my_binary
   # PROJECT_NAME=my_binary
   ```

4. **Start service**:
   ```bash
   docker-compose -f docker-compose.pyghidra.yml up -d
   ```

5. **Verify deployment**:
   ```bash
   docker logs -f ghidra-mcp-bridge-pyghidra
   curl http://localhost:8803/api/basic_info
   ```

#### Advantages

- ✅ Containerized deployment
- ✅ Reproducible environment
- ✅ Easy to manage with Docker Compose
- ✅ No GUI required

#### Limitations

- ❌ **Cannot use GUI while Docker is running** (Non-Shared Project limitation)
- ⚠️ Data in volume mount (not Server-managed)
- ❌ No version control
- ❌ No AI-human collaboration possible
- ⚠️ Container restart requires remounting

#### Use Cases

- **Fully automated** analysis of single binaries (no human review)
- CI/CD integration (batch processing)
- Testing Docker deployment
- Development without GUI
- ⚠️ **NOT for**: Any scenario requiring GUI access during analysis

#### Detailed Documentation

See [docker/QUICKSTART.pyghidra.md](../docker/QUICKSTART.pyghidra.md)

---

### Docker + Ghidra Server

**✅ The ONLY way to use AI (Docker) + GUI (human) simultaneously!**

**Configuration**: `PROJECT_MODE=server` in `.env` + Server connection variables

**Recommended for all production deployments and AI-human collaboration.**

#### Deployment Options

There are now **two ways** to set up Ghidra Server mode:

1. **Auto-Deploy Server** ⭐ (Recommended) - Server deployed automatically with one command
2. **Manual Server Setup** (Advanced) - Custom server configuration

##### Option 1: Auto-Deploy Server (Easiest) ⭐

**Use the pre-configured `docker-compose.with-server.yml` for zero-configuration setup:**

```bash
cd docker
cp .env.example .env
# Defaults work fine - no configuration needed!

# Start both Bridge and Server
make up-with-server
# Or: docker-compose -f docker-compose.with-server.yml up -d
```

**What this does:**
- ✅ Deploys Ghidra Server (blacktop/ghidra:12.0-server)
- ✅ Creates default repository `/default`
- ✅ Configures Bridge to connect automatically
- ✅ Enables anonymous access (no SSH keys needed)
- ✅ Sets up persistent Docker volumes

**Connect Ghidra GUI:**
```
File → New Project → Shared Project
  Server: localhost
  Port: 13100
  User: <leave empty for anonymous>
  Repository: /default
```

**Commands:**
```bash
make logs              # View Bridge logs
make logs-server       # View Server logs
make down-with-server  # Stop all services
```

**Data Persistence:**
Data is stored in Docker volumes that persist across restarts:
- `ghidra-mcp-server-repos` - Repository data
- `ghidra-mcp-server-config` - Server configuration

**Optional SSH Authentication:**
If you want authenticated access, edit `.env` before starting:
```bash
GHIDRA_SERVER_USERS=ai_analyst,human_analyst
GHIDRA_SERVER_USER=ai_analyst
HOST_SSH_KEYSTORE=./ssh-keys

# Generate keys
mkdir -p docker/ssh-keys
ssh-keygen -t rsa -b 2048 -f docker/ssh-keys/ssh_key -N ""
```

See [docker/QUICKSTART.md - Auto-Deploy Section](../docker/QUICKSTART.md#alternative-auto-deploy-ghidra-server-recommended-) for detailed guide.

##### Option 2: Manual Server Setup (Advanced)

**For custom configurations or connecting to existing servers:**

#### Architecture (Both Options)

```
┌─────────────────────────────────────────────────┐
│           Ghidra Server (Docker)                │
│  Repository: /repos/my_project                  │
│  - Persistent storage (Volume)                  │
│  - Version control                              │
│  - User management                              │
└────────┬──────────────────────┬─────────────────┘
         │                      │
         │ User: "ai_analyst"   │ User: "human_analyst"
         v                      v
┌────────────────────┐  ┌──────────────────────┐
│  MCP Bridge        │  │  Ghidra GUI          │
│  (Docker)          │  │  (Workstation)       │
│  - AI automation   │  │  - Interactive       │
│  HTTP API :8803    │  │  - Manual review     │
│  MCP SSE  :8804    │  │                      │
└────────────────────┘  └──────────────────────┘
```

#### Why Connect to Ghidra Server for Production?

**Critical problem with Local Project connection:**
- ❌ **Docker locks the project** - GUI cannot open it simultaneously!
- ❌ No AI-human collaboration possible
- ❌ No version control
- ⚠️ Data tied to volume mount
- ⚠️ Container restart = remount risk

**Ghidra Server connection solves this:**
- ✅ **Shared Project** - Docker and GUI can work together!
- ✅ **AI + human parallel work** - Each as independent user
- ✅ **Persistent storage** - Data survives container deletion
- ✅ **Version control** - Built-in conflict management
- ✅ **Audit trail** - Track who made what changes
- ✅ **Professional architecture** - Industry-standard approach

### Prerequisites

- Docker and Docker Compose installed
- Ghidra 12.0+ (for GUI user)
- 8GB RAM recommended
- Network access between containers

### Setup Steps

#### 1. Generate SSH Keys

```bash
mkdir -p ~/.ghidra

# AI analyst key (for MCP Bridge)
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/ai_analyst_key -N ""

# Human analyst key (for Ghidra GUI)
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/human_analyst_key -N ""
```

#### 2. Create docker-compose.yml

```yaml
version: '3.8'

services:
  ghidra-server:
    image: blacktop/ghidra:12.0-server
    container_name: ghidra-server
    ports:
      - "13100-13102:13100-13102"
    volumes:
      - ./ghidra-repos:/repos:rw
      - ./ghidra-config:/ghidra/.ghidraServer:rw
    environment:
      - MAXMEM=4G
      - GHIDRA_USERS=ai_analyst human_analyst
    restart: unless-stopped

  ghidra-bridge:
    image: ghidra-bridge:pyghidra
    depends_on:
      - ghidra-server
    environment:
      - PROJECT_MODE=server
      - GHIDRA_SERVER_HOST=ghidra-server
      - GHIDRA_SERVER_PORT=13100
      - GHIDRA_SERVER_USER=ai_analyst
      - GHIDRA_SERVER_REPO=/shared
      - PROJECT_NAME=my_project
      - GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
    volumes:
      - ~/.ghidra/ai_analyst_key:/root/.ghidra/ssh_key:ro
      - ./logs:/app/logs:rw
    ports:
      - "8803:8803"
      - "8804:8804"
    restart: unless-stopped
```

#### 3. Configure Server Users

```bash
# Start Server
docker-compose up -d ghidra-server

# Enter Server container
docker exec -it ghidra-server /bin/bash

# Add users
ghidra-server-admin add-user ai_analyst
ghidra-server-admin add-user human_analyst

# Create repository
ghidra-server-admin create-repository /shared

# Grant access
ghidra-server-admin grant-access /shared ai_analyst
ghidra-server-admin grant-access /shared human_analyst

exit
```

Add SSH public keys to Server's `authorized_keys`.

#### 4. Start MCP Bridge

```bash
docker-compose up -d ghidra-bridge
docker logs -f ghidra-bridge
```

#### 5. Configure GUI User

In Ghidra GUI on workstation:
- File → New Project → Shared Project
- Server: `localhost:13100` (or server hostname)
- User: `human_analyst`
- Repository: `/shared`
- Configure SSH key: `~/.ghidra/human_analyst_key`

#### 6. Verify Collaboration

```bash
# Test AI analyst
curl http://localhost:8803/api/basic_info
# Should show: User: ai_analyst

# Rename via MCP
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "rename.function", "name": "FUN_00401000", "new_name": "ai_named"}'

# Check in GUI - should see the rename
# Make changes in GUI - should sync to MCP
```

#### Advantages

- ✅ Production-ready architecture
- ✅ Data persistence across container restarts
- ✅ Multi-user concurrent access
- ✅ Built-in version control
- ✅ User permission isolation
- ✅ AI-human collaboration workflow

#### Use Cases

- Production AI-assisted reverse engineering
- Team collaboration (multiple analysts)
- Long-running analysis projects
- Critical infrastructure (need data durability)
- Multi-AI agent scenarios

### Data Persistence Test

```bash
# Make changes via MCP
curl -X POST http://localhost:8803/api/v1/edit \
  -H "Content-Type: application/json" \
  -d '{"action": "comment.set", "name": "main", "type": "PLATE", "text": "Test"}'

# Destroy all containers
docker-compose down

# Verify data still exists
ls -la ./ghidra-repos/shared/

# Restart
docker-compose up -d

# Verify changes preserved
curl "http://localhost:8803/api/v1/view?q=main&type=decompile"
# Should still see "Test" comment
```

### Detailed Documentation

See [README.md - Ghidra Server Mode](../README.md#ghidra-server-mode--production-recommended) and [examples/docker/ghidra-server/](../examples/docker/ghidra-server/)

---

## Migration Paths

### From Local GUI to Docker Mode

**Scenario**: You want containerized deployment but keep single-user workflow.

**Steps**:
1. Stop the GUI server
2. Copy Ghidra project to a shared location
3. Follow Docker + Local Project setup (set `PROJECT_MODE=local`)
4. Update AI client to point to `localhost:8804`

**Considerations**:
- Project files must be accessible to Docker
- Check volume mount permissions
- May need to re-analyze binary in headless mode

### From Local Project to Server Connection (Docker)

**Scenario**: You need multi-user collaboration or better persistence.

**Steps**:
1. Stop Docker container
2. Deploy Ghidra Server (add to docker-compose.yml)
3. Create repository and users
4. Import existing project to Server repository:
   ```bash
   # In Server container
   ghidra-server-admin import-project /path/to/local/project /shared my_project
   ```
5. Update `.env`: Change `PROJECT_MODE=local` to `PROJECT_MODE=server`
6. Add Server connection variables to `.env`
7. Restart container
8. Test with GUI user

**Considerations**:
- Project import may take time for large binaries
- Need to set up SSH authentication
- Just need to update `.env` file!

### From Local GUI to Docker + Server

**Scenario**: Direct upgrade from development to production.

**Steps**:
1. Stop Local GUI server
2. Deploy full Docker stack with Server (set `PROJECT_MODE=server`)
3. In Ghidra GUI, change from local to shared project
4. Connect to Server with SSH authentication
5. Verify both GUI and MCP Bridge can access

**Considerations**:
- Most significant architecture change
- Plan for downtime during migration
- Test thoroughly before production use

---

## Production Best Practices

### Security

**1. SSH Key Management**
- Use strong keys (RSA 4096-bit minimum)
- Separate keys for each user/agent
- Store keys securely (never commit to git)
- Rotate keys periodically

**2. Network Security**
- Bind to localhost for local-only access
- Use reverse proxy (nginx) for external access
- Enable TLS for production deployments
- Firewall rules to restrict port access

**3. User Permissions**
- Create separate users for AI vs human
- Grant minimal required permissions
- Audit user actions regularly

### Performance

**1. Resource Allocation**
- Minimum 8GB RAM for Ghidra Server
- Allocate 4-8GB to JVM (`MAXMEM`)
- Use SSD for repository storage
- Monitor container resource usage

**2. Optimization**
- Pre-analyze binaries before deployment
- Use indexed storage for large projects
- Limit concurrent MCP requests
- Cache frequently accessed data

### Reliability

**1. Data Backup**
```bash
# Backup Ghidra repository
tar -czf backup-$(date +%Y%m%d).tar.gz ./ghidra-repos/

# Automated backup (cron)
0 2 * * * tar -czf /backups/ghidra-$(date +\%Y\%m\%d).tar.gz /path/to/ghidra-repos/
```

**2. Monitoring**
- Health checks in Docker Compose
- Log aggregation (Filebeat, Logstash)
- Alert on container failures
- Monitor disk usage

**3. High Availability**
- Use Docker Swarm or Kubernetes for orchestration
- Multiple Server replicas (advanced)
- Load balancing for Bridge instances

### Maintenance

**1. Regular Updates**
- Keep Ghidra updated (12.0 → 12.1, etc.)
- Update Docker images
- Patch security vulnerabilities
- Test updates in staging first

**2. Log Management**
```yaml
# In docker-compose.yml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "5"
```

**3. Database Cleanup**
- Purge old versions in Server repository
- Clean up unused branches
- Archive completed projects

---

## Troubleshooting

### Common Issues

**Container won't start**
```bash
# Check logs
docker logs ghidra-bridge

# Common causes:
# - Insufficient memory
# - Project path not mounted
# - Port conflicts
```

**Server connection failed**
```bash
# Test network
docker exec ghidra-bridge ping ghidra-server

# Check ports
docker exec ghidra-bridge nc -zv ghidra-server 13100
```

**SSH authentication failed**
```bash
# Verify key permissions
chmod 600 ~/.ghidra/ai_analyst_key

# Check key is mounted
docker exec ghidra-bridge ls -la /root/.ghidra/ssh_key
```

**MCP client can't connect**
```bash
# Test SSE endpoint
curl http://localhost:8804/sse

# Check firewall
# Restart client (Claude Desktop)
```

### Getting Help

- **Documentation**: [README.md](../README.md), [CLAUDE.md](../CLAUDE.md)
- **Examples**: [examples/docker/](../examples/docker/)
- **Issues**: [GitHub Issues](https://github.com/Hao17/LiteGhidraMCP/issues)

---

## Summary

| Deployment Mode | Configuration | When to Use | Key Benefit |
|-----------------|---------------|-------------|-------------|
| **Local GUI** | Run in Ghidra GUI | Daily RE work | Interactive, fast iteration |
| **Docker + Local Project** | `PROJECT_MODE=local` | Quick testing | Containerized, reproducible |
| **Docker + Ghidra Server** ⭐ | `PROJECT_MODE=server` | Production | Persistent, collaborative |

**Key Insight**: Docker mode is a single deployment - just change `PROJECT_MODE` in `.env`!

**Recommendation**: Start with Local GUI for learning, move to Docker + Server for production.
