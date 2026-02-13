# Docker Architecture

This document describes the architecture of Ghidra MCP Bridge when running in Docker.

## Overview

Ghidra MCP Bridge in Docker runs Ghidra in **headless mode** with an HTTP API server and MCP SSE proxy, enabling AI-powered reverse engineering workflows without a GUI.

## Architecture Diagram

### Local Project Mode

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Host Machine                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Ghidra Shared Project (File System)                         │  │
│  │  /Users/user/ghidra-projects/my_binary/                      │  │
│  │  ├── my_binary.gpr (project config)                          │  │
│  │  └── my_binary.rep/ (project repository)                     │  │
│  │      ├── idata/                                               │  │
│  │      ├── user/                                                │  │
│  │      └── versioned/                                           │  │
│  └────────────────────┬─────────────────────────────────────────┘  │
│                       │ bind mount (volume)                        │
│  ┌────────────────────v─────────────────────────────────────────┐  │
│  │         Docker Container: ghidra-mcp-bridge                  │  │
│  │                                                              │  │
│  │  /ghidra-projects/ ← mounted project directory              │  │
│  │                                                              │  │
│  │  ┌───────────────────────────────────────────────────────┐  │  │
│  │  │  analyzeHeadless Process                              │  │  │
│  │  │  analyzeHeadless /ghidra-projects my_binary           │  │  │
│  │  │    -scriptPath /app                                   │  │  │
│  │  │    -postScript ghidra_mcp_server.py                   │  │  │
│  │  │                                                        │  │  │
│  │  │  Loads project → Ghidra state object cached           │  │  │
│  │  └───────────────────────┬───────────────────────────────┘  │  │
│  │                          │                                   │  │
│  │  ┌───────────────────────v───────────────────────────────┐  │  │
│  │  │  ghidra_mcp_server.py                                 │  │  │
│  │  │  - HTTP JSON API (ThreadingHTTPServer)                │  │  │
│  │  │  - Auto-loads api/ and api_v1/ modules (@route)       │  │  │
│  │  │  - Spawns MCP SSE proxy subprocess                    │  │  │
│  │  └───────┬────────────────────────────────┬──────────────┘  │  │
│  │          │                                │                  │  │
│  │  ┌───────v────────┐              ┌────────v─────────┐       │  │
│  │  │  HTTP Server   │              │  MCP SSE Proxy   │       │  │
│  │  │  :8803         │              │  :8804           │       │  │
│  │  │  /api/*        │              │  /sse            │       │  │
│  │  │  /_reload      │              │  (subprocess)    │       │  │
│  │  └───────┬────────┘              └────────┬─────────┘       │  │
│  └──────────┼─────────────────────────────────┼────────────────┘  │
│             │ port 8803                       │ port 8804         │
│             │                                 │                   │
└─────────────┼─────────────────────────────────┼───────────────────┘
              │                                 │
              v                                 v
    ┌─────────────────────┐         ┌─────────────────────┐
    │  HTTP API Clients   │         │   MCP Clients       │
    │  - curl             │         │   - Claude Desktop  │
    │  - scripts          │         │   - Coco            │
    │  - custom tools     │         │   - Custom MCP      │
    └─────────────────────┘         └─────────────────────┘
```

### Ghidra Server Mode

```
┌──────────────────────────────────────────────────────────────┐
│                    Ghidra Server (External)                  │
│            ghidra://ghidra-server.local:13100/shared         │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Project Repository                                    │ │
│  │  /repos/shared/my_binary_project/                      │ │
│  │  - Multi-user access control                           │ │
│  │  - Version history                                     │ │
│  │  - Locking mechanism                                   │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │ network (port 13100)
                         │
┌────────────────────────v─────────────────────────────────────┐
│         Docker Container: ghidra-mcp-bridge                  │
│                                                              │
│  analyzeHeadless Process:                                   │
│  analyzeHeadless                                            │
│    ghidra://ghidra-server.local:13100/shared                │
│    my_binary_project                                        │
│    -connect analyst                                         │
│    -scriptPath /app                                         │
│    -postScript ghidra_mcp_server.py                         │
│                                                              │
│  [Same HTTP + MCP architecture as local mode]               │
│                                                              │
│  HTTP :8803  │  MCP SSE :8804                               │
└──────────┬───┴────────┬─────────────────────────────────────┘
           │            │
           v            v
       API Clients   MCP Clients
```

## Component Breakdown

### 1. entrypoint.sh

**Purpose**: Container startup orchestration

**Responsibilities**:
- Parse environment variables (`PROJECT_MODE`, `PROJECT_PATH`, etc.)
- Build `analyzeHeadless` command based on project mode
- Validate project directory/server connection
- Start Ghidra headless process

**Key decisions**:
- **Local mode**: Uses `-scriptPath /app` to find scripts
- **Server mode**: Uses `ghidra://` URL and `-connect` parameter

### 2. analyzeHeadless

**Purpose**: Ghidra's headless analysis tool

**Configuration**:
```bash
# Local mode
analyzeHeadless /ghidra-projects my_binary \
    -scriptPath /app \
    -postScript ghidra_mcp_server.py

# Server mode
analyzeHeadless ghidra://server:13100/repo my_binary \
    -connect analyst \
    -scriptPath /app \
    -postScript ghidra_mcp_server.py
```

**Behavior**:
- Loads the specified project
- Creates Ghidra state object
- Executes `-postScript` (ghidra_mcp_server.py)
- Keeps running as long as the script is active

### 3. ghidra_mcp_server.py

**Purpose**: Main server entry point

**Startup sequence**:
1. Cache Ghidra state object (`_cached_state = state`)
2. Scan and load API modules from `api/` and `api_v1/`
3. Register `@route` decorated functions as HTTP endpoints
4. Start HTTP server (ThreadingHTTPServer on port 8803)
5. Spawn MCP SSE proxy subprocess (`scripts/mcp_sse_proxy.py`)
6. Enter daemon mode (keeps container running)

**Key features**:
- **Hot reload**: `GET /_reload` reloads API modules without restarting
- **Health check**: `GET /api/status` for Docker health monitoring
- **Thread safety**: Uses daemon threads to preserve Ghidra state

### 4. MCP SSE Proxy

**Purpose**: Translate MCP protocol to HTTP API calls

**Architecture**:
```
MCP Client (SSE) ←→ mcp_sse_proxy.py ←→ HTTP API (localhost:8803)
```

**Why separate process?**
- Avoids Jep threading restrictions (Ghidrathon limitation)
- Isolates MCP protocol handling from Ghidra internals
- Easier to debug and restart independently

**Communication**:
- **Inbound**: SSE stream from MCP clients (port 8804)
- **Outbound**: HTTP requests to localhost:8803 (same container)

### 5. API Modules

**Structure**:
```
api/
├── basic_info.py     # GET /api/basic_info
├── search.py         # GET /api/search/*
├── view.py           # GET /api/view/*
├── rename.py         # GET /api/rename/*
├── datatype.py       # GET /api/datatype/*
└── ...

api_v1/
├── search.py         # GET /api/v1/search
├── view.py           # GET /api/v1/view
├── list.py           # GET /api/v1/list
└── edit.py           # POST /api/v1/edit
```

**Loading mechanism**:
- Server scans `api/` and `api_v1/` directories at startup
- Imports all `.py` modules (except `__init__.py`)
- Registers functions decorated with `@route(path)`
- Hot reload via `/_reload` re-imports changed modules

### 6. utils/project_loader.py

**Purpose**: Validate and load Ghidra projects

**Functions**:
- `get_project_config()` - Parse environment variables
- `validate_local_project()` - Check .gpr and .rep files
- `load_project(state)` - Verify project loaded correctly

**Usage**:
- Called by `ghidra_mcp_server.py` during startup
- Provides detailed error messages for troubleshooting
- Supports both local and server modes

## Data Flow

### API Request Flow

```
1. Client sends HTTP request
   ↓
2. ThreadingHTTPServer receives request
   ↓
3. Route dispatcher finds matching @route function
   ↓
4. API function executes using cached Ghidra state
   ↓
5. Ghidra API calls (getCurrentProgram, etc.)
   ↓
6. JSON response generated
   ↓
7. Response sent to client
```

### MCP Request Flow

```
1. MCP client sends tool call via SSE
   ↓
2. mcp_sse_proxy.py receives MCP request
   ↓
3. Proxy translates to HTTP API call
   ↓
4. HTTP request to localhost:8803/api/v1/*
   ↓
5. [Same as API Request Flow above]
   ↓
6. HTTP response received by proxy
   ↓
7. Proxy formats as MCP response
   ↓
8. SSE stream sends response to client
```

## Project Storage Modes

### Local Mode (Volume Mount)

**Advantages**:
- Simple setup (just mount a directory)
- Direct file access (fast)
- No external dependencies
- Easy backup (copy directory)

**Use cases**:
- Single-user analysis
- Development/testing
- Offline environments
- CI/CD pipelines

**Limitations**:
- No built-in multi-user access control
- Manual synchronization for collaboration
- File locking at OS level only

### Server Mode (Ghidra Server)

**Advantages**:
- Multi-user collaboration
- Built-in version control
- Fine-grained access control
- Centralized project management

**Use cases**:
- Team collaboration
- Shared analysis workflows
- AI agent as collaborative participant
- Enterprise deployments

**Limitations**:
- Requires Ghidra Server setup
- Network dependency
- More complex configuration

## Health Monitoring

### Docker Health Check

**Mechanism**:
```yaml
healthcheck:
  test: ["CMD", "/healthcheck.sh"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

**What it checks**:
- HTTP API responds to `/api/status`
- Returns 200 OK status
- Response body contains valid JSON

**Benefits**:
- Automatic container restart if unhealthy
- Integration with orchestration (Kubernetes, Swarm)
- Monitoring alerts (Prometheus, etc.)

## Logging

### Log Locations

**Container**:
- `/app/logs/` - Application logs
- stdout - Docker captures for `docker logs`

**Host** (via volume mount):
- `./logs/` - Persistent logs across container restarts

### Log Levels

Controlled by `LOG_LEVEL` environment variable:
- `DEBUG` - Verbose (development)
- `INFO` - Default (production)
- `WARNING` - Important events only
- `ERROR` - Errors only

## Security Considerations

### Network Isolation

**Default**: Binds to `0.0.0.0` inside container

**Recommended for production**:
- Use reverse proxy (nginx, Traefik)
- Enable authentication (API keys, OAuth)
- Use TLS/SSL for remote access

### Project Access

**Local mode**:
- Container needs read/write access to volume
- File permissions managed by Docker user mapping

**Server mode**:
- Credentials passed via environment variables
- Consider using Docker secrets for passwords
- Encrypt network traffic (Ghidra Server SSL)

### Best Practices

1. **Don't expose ports publicly** without authentication
2. **Use specific image tags**, not `latest`
3. **Limit container resources** (CPU, memory)
4. **Rotate passwords** regularly (server mode)
5. **Monitor logs** for suspicious activity

## Performance Tuning

### Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 8G
    reservations:
      memory: 4G
```

### Ghidra Analysis Options

Set via environment variables or startup parameters:
- `AUTO_ANALYZE=false` - Skip auto-analysis on load
- `ANALYZE_TIMEOUT=3600` - Timeout for analysis tasks

### API Caching

- Ghidra state cached at startup (no re-initialization)
- Program objects reused across requests
- Hot reload only re-imports changed modules

## Troubleshooting

### Container won't start

**Check**:
1. Docker logs: `docker logs ghidra-mcp-bridge`
2. Volume mount permissions
3. Environment variables in `.env`

### API not responding

**Check**:
1. Health status: `docker inspect --format='{{.State.Health.Status}}' ghidra-mcp-bridge`
2. Port mapping: `docker ps`
3. Firewall rules

### Project load failure

**Check**:
1. Project files exist (local mode)
2. Server is reachable (server mode)
3. Credentials are correct
4. Project name matches

## Future Enhancements

- **Multi-project support**: Load multiple projects simultaneously
- **Kubernetes deployment**: Helm charts and operators
- **Horizontal scaling**: Multiple bridge instances behind load balancer
- **Metrics export**: Prometheus integration
- **WebSocket support**: Real-time push notifications
- **Plugin system**: Custom API modules via configuration

## References

- [Docker Deployment Guide](../setup/docker-deployment.md)
- [MCP Client Configuration](../setup/mcp-clients.md)
- [API Reference](../api/api-reference.md)
