# Ghidra Server Mode (SSH Authentication)

This example demonstrates how to connect Ghidra MCP Bridge to a Ghidra Server using SSH key authentication.

## Features

- ✅ **Ghidra 12.0.3** - Latest official release
- ✅ **SSH Key Authentication** - Secure, non-interactive authentication
- ✅ **No Password Prompts** - Fully automated Docker deployment
- ✅ **SSL Compatibility** - Works with Docker host networking
- ❌ **Password Authentication Removed** - For security

## Quick Start

### 1. Generate SSH Key

Run the automated setup script:

```bash
cd /Users/syec/Repos/Onmi/OnmiPy/Bridge
./scripts/setup_ssh_auth.sh bridge
```

This will:
- Create `~/.ghidra/bridge_key` (private key)
- Create `~/.ghidra/bridge_key.pub` (public key)
- Set correct permissions
- Display instructions

### 2. Configure Ghidra Server

Add the public key to Ghidra Server:

**Option A: Using svrAdmin (Recommended)**
```bash
# On Ghidra Server machine
cd /path/to/ghidra/server
./svrAdmin

# In svrAdmin console
> add user bridge
> set ssh-key bridge <paste-public-key>
> exit
```

**Option B: Manual File Configuration**
```bash
# On Ghidra Server machine
cd /path/to/ghidra/server/users/bridge
cat >> authorized_keys << 'EOF'
<paste-public-key-here>
EOF
chmod 644 authorized_keys
```

### 3. Configure Docker

Edit `.env.pyghidra`:

```bash
# Server Connection
GHIDRA_SERVER_HOST=host.docker.internal  # Or your server IP
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge

# SSH Authentication
GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key

# Repository
GHIDRA_SERVER_REPO=/
PROJECT_NAME=my_project
```

### 4. Start Container

```bash
docker-compose -f docker-compose.pyghidra.yml up -d
```

### 5. Verify Connection

```bash
# Check logs
docker logs -f ghidra-mcp-bridge-pyghidra-server

# Expected output:
# [PyGhidra-MCP-Bridge] Connecting to Ghidra Server: host.docker.internal:13100
# [PyGhidra-MCP-Bridge] User: bridge
# [PyGhidra-MCP-Bridge] Authentication: SSH key (/root/.ghidra/ssh_key)
# [PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed
# [PyGhidra-MCP-Bridge] ✓ Connected to server
# [PyGhidra-MCP-Bridge] Server user: bridge

# Test API
curl http://localhost:8803/api/basic_info
```

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PROJECT_MODE` | Project mode | `server` |
| `GHIDRA_SERVER_HOST` | Server hostname | `host.docker.internal` |
| `GHIDRA_SERVER_PORT` | Server port | `13100` |
| `GHIDRA_SERVER_USER` | Username | `bridge` |
| `GHIDRA_SERVER_KEYSTORE` | SSH private key path (container) | `/root/.ghidra/ssh_key` |
| `GHIDRA_SERVER_REPO` | Repository name | `/` or `/my_repo` |
| `PROJECT_NAME` | Project name | `my_project` |

### Docker Volumes

| Host Path | Container Path | Mode | Purpose |
|-----------|---------------|------|---------|
| `~/.ghidra/bridge_key` | `/root/.ghidra/ssh_key` | `ro` | SSH private key |
| `./logs` | `/app/logs` | `rw` | Log persistence |

## Architecture

```
┌─────────────────────┐
│   Docker Container  │
│                     │
│  ┌──────────────┐   │      SSH Key Auth      ┌─────────────────┐
│  │   PyGhidra   │   │ ───────────────────────>│  Ghidra Server  │
│  │  MCP Bridge  │   │   (host.docker.internal)│   (Port 13100)  │
│  │              │   │                         │                 │
│  │  Ghidra 12.0.3  │                         │  Repositories   │
│  │  HTTP API    │   │                         │  - Projects     │
│  │  Port 8803   │   │                         │  - Binaries     │
│  └──────────────┘   │                         └─────────────────┘
│         ▲           │
│         │           │
│    ~/.ghidra/       │
│    bridge_key (ro)  │
│                     │
└─────────────────────┘
         │
         │ HTTP API
         ▼
  ┌──────────────┐
  │  Claude Code │
  │  MCP Client  │
  └──────────────┘
```

## Troubleshooting

### Connection Failed

**Error:** `Failed to establish server connection`

**Solutions:**
1. Verify server is running:
   ```bash
   nc -zv localhost 13100
   ```

2. Check Docker networking:
   ```bash
   docker exec ghidra-mcp-bridge-pyghidra-server ping host.docker.internal
   ```

3. Verify SSH key is mounted:
   ```bash
   docker exec ghidra-mcp-bridge-pyghidra-server ls -la /root/.ghidra/ssh_key
   ```

### Authentication Failed

**Error:** `Authentication failed` or `Access denied`

**Solutions:**
1. Verify public key on server:
   ```bash
   # On server
   cat /path/to/ghidra/server/users/bridge/authorized_keys
   ```

2. Check key fingerprints match:
   ```bash
   ssh-keygen -lf ~/.ghidra/bridge_key
   ssh-keygen -lf ~/.ghidra/bridge_key.pub
   ```

3. Restart Ghidra Server after adding keys

### Key Not Found

**Error:** `SSH keystore file not found`

**Solutions:**
1. Verify key exists on host:
   ```bash
   ls -la ~/.ghidra/bridge_key
   ```

2. Check docker-compose.yml volume mount:
   ```yaml
   volumes:
     - ~/.ghidra/bridge_key:/root/.ghidra/ssh_key:ro
   ```

3. Rebuild container:
   ```bash
   docker-compose -f docker-compose.pyghidra.yml down
   docker-compose -f docker-compose.pyghidra.yml up -d
   ```

### Permission Denied

**Error:** `WARNING: SSH keystore permissions are 777`

**Solution:**
```bash
chmod 600 ~/.ghidra/bridge_key
docker-compose -f docker-compose.pyghidra.yml restart
```

## Comparison with Standard Version

| Feature | Standard (Ghidra 11.0) | PyGhidra (Ghidra 12.0.3) |
|---------|----------------------|--------------------------|
| Ghidra Version | 11.0 (2021) | 12.0.3 (2026-02-10) ✅ |
| Python Integration | Ghidrathon (3rd party) | PyGhidra (official) ✅ |
| Server Support | ✅ analyzeHeadless | ✅ Native Python API |
| Authentication | Password pipe | SSH key only ✅ |
| SSL Support | Manual | Auto-configured ✅ |
| Performance | Good | Better (native) ✅ |

## API Examples

```bash
# Basic info
curl http://localhost:8803/api/basic_info

# Search functions
curl "http://localhost:8803/api/search/functions?q=main&limit=10"

# Decompile function
curl "http://localhost:8803/api/view/decompile?name=main"

# List symbols
curl "http://localhost:8803/api/v1/list?types=functions,classes"
```

## Security Notes

1. **Never commit SSH private keys** to version control
2. **Use 600 permissions** on private key file
3. **Rotate keys periodically** (e.g., quarterly)
4. **One key per environment** (dev, staging, prod)
5. **Backup keys securely** (encrypted)

## Production Deployment

For production use, consider:

1. **Docker Secrets** instead of volume mounts:
   ```bash
   docker secret create ghidra_ssh_key ~/.ghidra/bridge_key
   ```

2. **Key rotation policy**:
   - Generate new keys every 90 days
   - Update server authorized_keys
   - Update Docker secret
   - Restart containers

3. **Monitoring**:
   - Log all authentication attempts
   - Alert on failed authentications
   - Track key usage

## References

- [SSH Key Authentication Guide](../../../docs/SSH_KEY_AUTHENTICATION.md)
- [PyGhidra Documentation](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- [Project README](../../../README.md)

## Support

For issues or questions:
- Check [SSH_KEY_AUTHENTICATION.md](../../../docs/SSH_KEY_AUTHENTICATION.md)
- Review [CLAUDE.md](../../../CLAUDE.md)
- Open an issue on GitHub
