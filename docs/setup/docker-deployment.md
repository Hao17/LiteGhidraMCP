# Docker Deployment Guide

This guide covers deploying Ghidra MCP Bridge as a Docker container for headless operation.

## Overview

The Docker deployment mode runs Ghidra in headless mode with the MCP Bridge, providing:

- **HTTP JSON API** (port 8803) for direct API access
- **MCP SSE server** (port 8804) for AI client integration
- **Project flexibility**: local volumes or Ghidra Server
- **Health monitoring** and automatic restart
- **Persistent logging**

## Architecture

### Local Project Mode

```
┌─────────────────────────────────────────────────────────────┐
│         Ghidra Shared Project (Host Volume)                 │
│         /path/to/project/                                   │
│         ├── my_binary.gpr                                   │
│         └── my_binary.rep/                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ mounted as /ghidra-projects
                         v
┌─────────────────────────────────────────────────────────────┐
│              Docker Container: ghidra-mcp-bridge            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Ghidra Headless                                     │  │
│  │  analyzeHeadless /ghidra-projects my_binary          │  │
│  │  -postScript ghidra_mcp_server.py                    │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                         │
│  ┌────────────────v─────────────────────────────────────┐  │
│  │  MCP Bridge                                          │  │
│  │  - HTTP API :8803                                    │  │
│  │  - MCP SSE  :8804                                    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                              │
         v                              v
    API Clients                   MCP Clients
    (curl, scripts)          (Claude, Coco)
```

### Ghidra Server Mode

```
┌─────────────────────────────────────┐
│      Ghidra Server                  │
│      ghidra://host:13100/repo       │
└──────────┬──────────────────────────┘
           │
           │ network connection
           v
┌─────────────────────────────────────┐
│  Docker Container: ghidra-bridge    │
│                                     │
│  analyzeHeadless                    │
│    ghidra://server:13100/repo       │
│    project_name                     │
│    -connect user                    │
│    -postScript ghidra_mcp_server.py │
│                                     │
│  MCP Bridge :8803 :8804             │
└─────────────────────────────────────┘
```

## Quick Start

### 1. Build the Docker image

```bash
cd docker
docker build -f Dockerfile -t ghidra-mcp-bridge:latest ..
```

Or use Docker Compose (builds automatically):

```bash
cd examples/docker/local-project
docker-compose up --build
```

### 2. Choose deployment mode

#### Local Project Mode

See [`examples/docker/local-project/`](../../examples/docker/local-project/)

```bash
cd examples/docker/local-project
# Edit .env to configure your project path
docker-compose up -d
```

#### Ghidra Server Mode

See [`examples/docker/ghidra-server/`](../../examples/docker/ghidra-server/)

```bash
cd examples/docker/ghidra-server
# Edit .env to configure server connection
docker-compose up -d
```

### 3. Verify deployment

```bash
# Check container status
docker ps

# View logs
docker logs ghidra-mcp-bridge

# Test API
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
```

## Configuration

### Environment Variables

All configuration is done via environment variables (see [`config/.env.example`](../../config/.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_HOST` | `0.0.0.0` | API server bind address |
| `GHIDRA_MCP_PORT` | `8803` | HTTP API port |
| `GHIDRA_MCP_SSE_PORT` | `8804` | MCP SSE port |
| `PROJECT_MODE` | `local` | `local` or `server` |
| `PROJECT_PATH` | `/ghidra-projects` | Local project directory (local mode) |
| `PROJECT_NAME` | `default` | Project name |
| `GHIDRA_SERVER_HOST` | - | Server hostname (server mode) |
| `GHIDRA_SERVER_PORT` | `13100` | Server port (server mode) |
| `GHIDRA_SERVER_USER` | - | Server username (server mode) |
| `GHIDRA_SERVER_REPO` | `/` | Server repository path (server mode) |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_DIR` | `/app/logs` | Log directory |

### Volume Mounts

**Local project mode** requires mounting your Ghidra project directory:

```yaml
volumes:
  - /path/to/your/ghidra-project:/ghidra-projects:rw
  - ./logs:/app/logs:rw
```

**Server mode** only needs log persistence:

```yaml
volumes:
  - ./logs:/app/logs:rw
```

### Port Mapping

```yaml
ports:
  - "8803:8803"  # HTTP API
  - "8804:8804"  # MCP SSE
```

To use different host ports:

```yaml
ports:
  - "9000:8803"  # Map host port 9000 to container port 8803
  - "9001:8804"
```

Then access via `http://localhost:9000/api/status`.

## Health Checks

The container includes automatic health monitoring:

```yaml
healthcheck:
  test: ["CMD", "/healthcheck.sh"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

Health check script (`docker/healthcheck.sh`) tests the `/api/status` endpoint.

Check health status:

```bash
docker inspect --format='{{.State.Health.Status}}' ghidra-mcp-bridge
```

## Logging

Logs are written to `/app/logs` inside the container and should be mounted to persist:

```yaml
volumes:
  - ./logs:/app/logs:rw
```

View live logs:

```bash
docker-compose logs -f ghidra-bridge
```

## Troubleshooting

### Container won't start

**Check logs:**
```bash
docker-compose logs ghidra-bridge
```

**Common issues:**

1. **Project directory not found (local mode)**
   ```
   ERROR: Project directory does not exist: /ghidra-projects
   ```
   **Solution**: Verify volume mount path in `docker-compose.yml` and ensure directory exists on host.

2. **Project files missing**
   ```
   Project file not found: /ghidra-projects/my_binary.gpr
   ```
   **Solution**: Ensure `PROJECT_NAME` matches the `.gpr` filename (without extension).

3. **Server connection failed (server mode)**
   ```
   Failed to connect to Ghidra Server or load project
   ```
   **Solution**: Verify server is running, hostname is correct, and credentials are valid.

### API not responding

**Check container health:**
```bash
docker ps
```

Look for `(unhealthy)` status. If unhealthy, check logs for errors.

**Test connectivity:**
```bash
docker exec ghidra-mcp-bridge curl http://localhost:8803/api/status
```

### Port conflicts

If ports 8803/8804 are already in use:

```bash
# Check what's using the port
lsof -i :8803

# Change ports in docker-compose.yml
ports:
  - "8805:8803"
  - "8806:8804"
```

### Permission issues

If you get permission denied errors accessing the project:

```bash
# Check file permissions on host
ls -la /path/to/your/ghidra-project/

# Ensure Docker has read/write access
chmod -R 755 /path/to/your/ghidra-project/
```

## Advanced Topics

### Custom Dockerfile

Create a custom Dockerfile for specific needs:

```dockerfile
FROM ghidra-mcp-bridge:latest

# Install additional Python packages
RUN pip3 install numpy pandas

# Copy custom scripts
COPY my_custom_api.py /app/api/

# Override entrypoint for custom startup
ENTRYPOINT ["/my-custom-entrypoint.sh"]
```

### Multi-Stage Builds

For smaller images, use multi-stage builds:

```dockerfile
FROM blacktop/ghidra:11.0 AS builder
# Build dependencies...

FROM blacktop/ghidra:11.0
COPY --from=builder /app /app
# Runtime configuration...
```

### Resource Limits

Limit container resources:

```yaml
services:
  ghidra-bridge:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          memory: 2G
```

### Running Behind a Reverse Proxy

Use nginx or Traefik for SSL termination and authentication:

```nginx
server {
    listen 443 ssl;
    server_name ghidra-api.example.com;

    location / {
        proxy_pass http://localhost:8803;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Production Checklist

- [ ] Use **specific image tags** (not `latest`)
- [ ] Configure **resource limits**
- [ ] Set up **log rotation** (Docker logging driver)
- [ ] Use **secrets** for passwords (not environment variables)
- [ ] Enable **TLS/SSL** (reverse proxy)
- [ ] Configure **monitoring** (Prometheus, Grafana)
- [ ] Set up **backup** for project data
- [ ] Test **disaster recovery** procedures
- [ ] Document **rollback** procedures
- [ ] Configure **firewall rules** (restrict port access)

## Next Steps

- Configure MCP clients: [`docs/setup/mcp-clients.md`](mcp-clients.md)
- API reference: [`docs/api/api-reference.md`](../api/api-reference.md)
- Troubleshooting: [`docs/troubleshooting.md`](../troubleshooting.md)
