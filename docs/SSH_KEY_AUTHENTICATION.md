# SSH Key Authentication for Ghidra Server

This guide explains how to set up SSH key authentication for PyGhidra MCP Bridge to connect to Ghidra Server securely.

## Overview

**Important Changes:**
- ❌ **Password authentication has been REMOVED** for security reasons
- ✅ **SSH key authentication is now REQUIRED** for authenticated access
- ✅ Anonymous access still supported (no authentication)

## Why SSH Keys?

1. **Security**: No passwords stored in environment variables or config files
2. **Automation**: No interactive prompts in Docker containers
3. **Best Practice**: Industry standard for server authentication
4. **Auditability**: Key-based access can be easily tracked and revoked

---

## Setup Guide

### Step 1: Generate SSH Key Pair

Generate a new SSH key pair for Ghidra Server authentication:

```bash
# Create .ghidra directory
mkdir -p ~/.ghidra

# Generate 4096-bit RSA key
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key -N ""
```

**Important Notes:**
- `-N ""` creates a key with **no passphrase** (required for non-interactive use)
- For production, consider using a passphrase with ssh-agent
- The key will be stored at:
  - Private key: `~/.ghidra/bridge_key`
  - Public key: `~/.ghidra/bridge_key.pub`

### Step 2: Configure Ghidra Server

#### Option A: Using Ghidra Server GUI

1. **Start Ghidra Server** (if not already running):
   ```bash
   cd /path/to/ghidra/server
   ./svrAdmin
   ```

2. **Add user** (if doesn't exist):
   ```bash
   ./svrAdmin
   > add user bridge
   ```

3. **Configure SSH public key**:
   - Copy public key content:
     ```bash
     cat ~/.ghidra/bridge_key.pub
     ```
   - In Ghidra Server admin, navigate to user `bridge`
   - Add the public key to the authorized keys

#### Option B: Using Server Files Directly

1. **Locate server users directory**:
   ```bash
   cd /path/to/ghidra/server/users
   ```

2. **Create user directory** (if doesn't exist):
   ```bash
   mkdir -p bridge
   cd bridge
   ```

3. **Add SSH public key**:
   ```bash
   # Copy public key to authorized_keys
   cat ~/.ghidra/bridge_key.pub > authorized_keys

   # Set proper permissions
   chmod 644 authorized_keys
   ```

4. **Restart Ghidra Server** to apply changes

### Step 3: Verify Key Permissions

SSH keys require specific permissions:

```bash
# Private key must be readable only by owner
chmod 600 ~/.ghidra/bridge_key

# Public key can be world-readable
chmod 644 ~/.ghidra/bridge_key.pub
```

### Step 4: Test Connection (Optional)

Test SSH key authentication manually:

```bash
# Using analyzeHeadless
echo "" | analyzeHeadless \
  ghidra://localhost:13100/ \
  test_project \
  -connect bridge \
  -keystore ~/.ghidra/bridge_key \
  -deleteProject
```

If successful, you should see:
```
REPORT: Connected to server
REPORT: User: bridge
```

---

## Docker Configuration

### Configuration File: `.env.pyghidra`

```bash
# Project Mode
PROJECT_MODE=server

# Server Connection
GHIDRA_SERVER_HOST=host.docker.internal  # Or your server IP
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge

# SSH Key Authentication
GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key  # Path inside container

# Repository
GHIDRA_SERVER_REPO=/
PROJECT_NAME=my_project
```

### Docker Compose Configuration

```yaml
# docker-compose.pyghidra.yml
services:
  ghidra-bridge:
    build:
      dockerfile: docker/Dockerfile.pyghidra

    env_file:
      - .env.pyghidra

    volumes:
      # Mount SSH private key (read-only)
      - ~/.ghidra/bridge_key:/root/.ghidra/ssh_key:ro

    extra_hosts:
      - "host.docker.internal:host-gateway"
```

### Start Docker Container

```bash
cd examples/docker/ghidra-server

# Build and start
docker-compose -f docker-compose.pyghidra.yml up -d

# Check logs
docker logs -f ghidra-mcp-bridge-pyghidra-server
```

**Expected Log Output:**
```
[PyGhidra-MCP-Bridge] Connecting to Ghidra Server: host.docker.internal:13100
[PyGhidra-MCP-Bridge] User: bridge
[PyGhidra-MCP-Bridge] Authentication: SSH key (/root/.ghidra/ssh_key)
[PyGhidra-MCP-Bridge] Installing headless authenticator with SSH key
[PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed
[PyGhidra-MCP-Bridge] ✓ Connected to server
[PyGhidra-MCP-Bridge] Server user: bridge
```

---

## Troubleshooting

### Error: "SSH keystore not found"

**Problem:** Container cannot find the SSH key

**Solution:**
1. Verify key exists on host:
   ```bash
   ls -la ~/.ghidra/bridge_key
   ```

2. Check Docker volume mount:
   ```bash
   docker inspect ghidra-mcp-bridge-pyghidra-server | grep -A5 Mounts
   ```

3. Verify path in `.env.pyghidra`:
   ```bash
   GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
   ```

### Error: "Authentication failed"

**Problem:** SSH key authentication rejected by server

**Solution:**
1. Verify public key is registered on server:
   ```bash
   # On Ghidra Server machine
   cat /path/to/ghidra/server/users/bridge/authorized_keys
   ```

2. Check key fingerprint matches:
   ```bash
   ssh-keygen -lf ~/.ghidra/bridge_key
   ssh-keygen -lf ~/.ghidra/bridge_key.pub
   ```

3. Check server logs for authentication errors

### Error: "WARNING: SSH keystore permissions are 777"

**Problem:** Key file permissions too permissive

**Solution:**
```bash
chmod 600 ~/.ghidra/bridge_key
```

### Error: "Connection refused"

**Problem:** Cannot reach Ghidra Server

**Solution:**
1. Verify server is running:
   ```bash
   netstat -an | grep 13100
   ```

2. Test from host machine:
   ```bash
   nc -zv localhost 13100
   ```

3. If using Docker, verify host.docker.internal:
   ```bash
   docker exec ghidra-mcp-bridge-pyghidra-server ping host.docker.internal
   ```

---

## Security Best Practices

### 1. Key Rotation

Rotate SSH keys periodically:

```bash
# Generate new key
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key_new -N ""

# Update server with new public key
# Test new key
# Remove old key from server
# Delete old key file
rm ~/.ghidra/bridge_key ~/.ghidra/bridge_key.pub
mv ~/.ghidra/bridge_key_new ~/.ghidra/bridge_key
mv ~/.ghidra/bridge_key_new.pub ~/.ghidra/bridge_key.pub
```

### 2. Key Storage

**Development:**
- Store in `~/.ghidra/` directory
- Use filesystem permissions (600)

**Production:**
- Use Docker Secrets:
  ```bash
  docker secret create ghidra_ssh_key ~/.ghidra/bridge_key
  ```

- Use Kubernetes Secrets:
  ```bash
  kubectl create secret generic ghidra-ssh-key \
    --from-file=ssh-key=~/.ghidra/bridge_key
  ```

### 3. Access Control

- **One key per user**: Don't share SSH keys between users
- **One key per environment**: Use different keys for dev/staging/prod
- **Audit access**: Regularly review authorized_keys on server

### 4. Backup

Backup SSH keys securely:

```bash
# Encrypt backup
tar czf - ~/.ghidra/bridge_key* | \
  gpg -c > ghidra_keys_backup.tar.gz.gpg

# Restore
gpg -d ghidra_keys_backup.tar.gz.gpg | tar xzf -
```

---

## Anonymous Access

For testing or public read-only access, anonymous mode is still supported:

```bash
# .env.pyghidra
PROJECT_MODE=server
GHIDRA_SERVER_HOST=host.docker.internal
GHIDRA_SERVER_PORT=13100

# Leave GHIDRA_SERVER_USER empty for anonymous
GHIDRA_SERVER_USER=
GHIDRA_SERVER_KEYSTORE=
```

**Note:** Anonymous access requires server configuration:
```bash
# On server
./svrAdmin
> anonymous access on
```

---

## Advanced Configuration

### Using SSH Agent (Interactive Mode)

For interactive use with passphrase-protected keys:

```bash
# Start ssh-agent
eval $(ssh-agent)

# Add key (will prompt for passphrase)
ssh-add ~/.ghidra/bridge_key

# Run with agent socket
docker run \
  -v $SSH_AUTH_SOCK:/ssh-agent \
  -e SSH_AUTH_SOCK=/ssh-agent \
  ghidra-mcp-bridge
```

### Multiple Keys for Different Servers

```bash
# Generate keys for different environments
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key_dev -N ""
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key_prod -N ""

# Configure different compose files
# dev: -v ~/.ghidra/bridge_key_dev:/root/.ghidra/ssh_key:ro
# prod: -v ~/.ghidra/bridge_key_prod:/root/.ghidra/ssh_key:ro
```

---

## References

- [Ghidra Server Documentation](https://ghidra.re/ghidra_docs/)
- [SSH Key Best Practices](https://www.ssh.com/academy/ssh/key)
- [Docker Secrets](https://docs.docker.com/engine/swarm/secrets/)
- [Project README](../README.md)

---

## Quick Reference

```bash
# Generate key
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key -N ""

# Fix permissions
chmod 600 ~/.ghidra/bridge_key

# View public key
cat ~/.ghidra/bridge_key.pub

# Test connection
analyzeHeadless ghidra://localhost:13100/ test -connect bridge -keystore ~/.ghidra/bridge_key

# Start Docker
cd docker/
make up-separated

# Check logs
make client-logs
```

---

## Migration from Password Auth

Password authentication was removed in favor of SSH keys (Feb 2026).

### Breaking Changes

1. **`GHIDRA_SERVER_PASSWORD` env var removed** — old configs using it will fail
2. **`GHIDRA_SERVER_KEYSTORE` required** for authenticated access (+ Docker volume mount)
3. **Must use `Dockerfile.pyghidra`** (Ghidra 12.0+)

### Still Compatible

- Anonymous access (no config changes needed)
- Local project mode (unaffected)
- All HTTP API endpoints (no changes)

### Migration Steps

1. Generate SSH key: `ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key -N ""`
2. Register public key on Ghidra Server (`svrAdmin` → `add user` / `set ssh-key`)
3. Replace `GHIDRA_SERVER_PASSWORD=xxx` with `GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key` in `.env`
4. Add volume mount in compose: `~/.ghidra/bridge_key:/root/.ghidra/ssh_key:ro`
5. Restart container

### Rollback

Checkout previous git version (`git checkout HEAD~1`) and use standard Dockerfile (Ghidra 11.0).
