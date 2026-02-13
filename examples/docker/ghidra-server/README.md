# Ghidra Server Mode - Docker Deployment

This example demonstrates deploying Ghidra MCP Bridge in Docker using a **Ghidra Server** for project storage.

## Prerequisites

1. **Ghidra Server** running and accessible (local or remote)
2. Valid user credentials for the Ghidra Server
3. Existing project on the server (or create one manually)
4. Docker and Docker Compose installed

## Architecture

```
┌──────────────────┐
│  Ghidra GUI      │
│  (User 1)        │
└────────┬─────────┘
         │
         v
┌────────────────────────────────────┐
│     Ghidra Server                  │
│     ghidra://host:13100/repo       │
└────────┬───────────────────────────┘
         │
         v
┌────────────────┐
│  Docker Bridge │
│  (AI Agent)    │
└────────────────┘
```

## Configuration Steps

### 1. Edit `.env` file

Update the following variables:

```bash
# Ghidra Server connection details
GHIDRA_SERVER_HOST=ghidra-server.example.com  # or IP address
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=analyst
GHIDRA_SERVER_REPO=/shared  # Repository path on server

# Project name on the server
PROJECT_NAME=my_shared_project
```

### 2. Set up authentication

**Option A: Environment variable (not recommended for production)**
```bash
export GHIDRA_SERVER_PASSWORD="your-password"
docker-compose up -d
```

**Option B: Docker secrets (recommended)**

Create a secret file:
```bash
echo "your-password" > ghidra_password.txt
docker secret create ghidra_password ghidra_password.txt
rm ghidra_password.txt
```

Update `docker-compose.yml` to use secrets:
```yaml
services:
  ghidra-bridge:
    secrets:
      - ghidra_password
    environment:
      - GHIDRA_SERVER_PASSWORD_FILE=/run/secrets/ghidra_password

secrets:
  ghidra_password:
    external: true
```

### 3. Verify server connectivity

Test connection before launching:
```bash
# From your host machine
telnet ghidra-server.example.com 13100
```

### 4. Launch the container

```bash
docker-compose up -d
```

### 5. Verify the service

Check logs:
```bash
docker-compose logs -f ghidra-bridge
```

Look for:
```
Connecting to Ghidra Server: ghidra-server.example.com:13100
Repository: /shared
User: analyst
Server project loaded: ghidra-server.example.com:13100/my_shared_project
```

Test API:
```bash
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
```

## Troubleshooting

### Cannot connect to Ghidra Server

Check network connectivity:
```bash
docker exec -it ghidra-mcp-bridge-server ping ghidra-server.example.com
```

Verify server is running:
```bash
# On the Ghidra Server host
netstat -an | grep 13100
```

### Authentication failed

Verify credentials:
- User exists on Ghidra Server
- Password is correct
- User has access to the specified repository

Check server logs for authentication errors.

### Project not found

Ensure the project exists on the server:
```bash
# Use Ghidra GUI to connect to server and verify project exists
# Or check server filesystem (if you have access)
```

## Advanced: Running Ghidra Server in Docker

You can run Ghidra Server alongside the bridge:

Uncomment the `ghidra-server` service in `docker-compose.yml`:

```yaml
services:
  ghidra-server:
    image: blacktop/ghidra:11.0-server
    container_name: ghidra-server
    ports:
      - "13100:13100"
    volumes:
      - ghidra-server-data:/repos
    environment:
      - GHIDRA_USERS=analyst:password

volumes:
  ghidra-server-data:
```

Update `.env`:
```bash
GHIDRA_SERVER_HOST=ghidra-server  # Docker service name
```

Launch both:
```bash
docker-compose up -d
```

## Security Considerations

1. **Never commit `.env` with passwords** to version control
2. Use **Docker secrets** for production deployments
3. Use **TLS/SSL** for Ghidra Server connections in production
4. Restrict network access to Ghidra Server (firewall rules)
5. Use **strong passwords** and change default credentials

## Stopping the Service

```bash
docker-compose down
```

To remove volumes (logs):
```bash
docker-compose down -v
```
