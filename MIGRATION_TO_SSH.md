# Migration Guide: Password to SSH Key Authentication

## Overview

This project has been updated to use **SSH key authentication only** for Ghidra Server connections in PyGhidra mode. Password authentication has been completely removed for security reasons.

## What Changed

### ❌ Removed Features

1. **Password Authentication**
   - `GHIDRA_SERVER_PASSWORD` environment variable removed
   - Interactive password prompts removed
   - Password piping via stdin removed

2. **Reason for Removal**
   - Security risk: passwords in environment variables
   - Interactive prompts incompatible with Docker automation
   - Best practice: use SSH keys for server authentication

### ✅ New Features

1. **SSH Key Authentication**
   - `GHIDRA_SERVER_KEYSTORE` environment variable
   - Automatic keystore validation
   - Permission checking and fixing
   - Docker volume mounting for keys

2. **Enhanced Security**
   - No passwords stored in configuration
   - Filesystem-based key protection
   - Easy key rotation
   - Audit trail via server logs

## Migration Steps

### For Existing Users

If you were using password authentication, follow these steps to migrate:

#### 1. Generate SSH Key

```bash
# Run automated setup
./scripts/setup_ssh_auth.sh bridge

# Or manual generation
mkdir -p ~/.ghidra
ssh-keygen -t rsa -b 4096 -f ~/.ghidra/bridge_key -N ""
chmod 600 ~/.ghidra/bridge_key
```

#### 2. Add Public Key to Ghidra Server

```bash
# Copy public key
cat ~/.ghidra/bridge_key.pub

# On Ghidra Server machine
cd /path/to/ghidra/server
./svrAdmin
> add user bridge  # If user doesn't exist
> set ssh-key bridge <paste-public-key>
> exit
```

#### 3. Update Configuration

**Before (Password Auth):**
```bash
# .env - OLD CONFIG
PROJECT_MODE=server
GHIDRA_SERVER_HOST=host.docker.internal
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge
GHIDRA_SERVER_PASSWORD=bridge123  # ❌ REMOVED
```

**After (SSH Key Auth):**
```bash
# .env.pyghidra - NEW CONFIG
PROJECT_MODE=server
GHIDRA_SERVER_HOST=host.docker.internal
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge
GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key  # ✅ NEW
```

#### 4. Update Docker Compose

**Before:**
```yaml
# docker-compose.yml - OLD
volumes:
  - ./logs:/app/logs:rw
```

**After:**
```yaml
# docker-compose.pyghidra.yml - NEW
volumes:
  - ./logs:/app/logs:rw
  - ~/.ghidra/bridge_key:/root/.ghidra/ssh_key:ro  # ✅ NEW
```

#### 5. Restart Container

```bash
# Stop old container
docker-compose down

# Start new container with SSH auth
docker-compose -f docker-compose.pyghidra.yml up -d
```

## Version Comparison

| Aspect | Old (Password) | New (SSH Key) |
|--------|----------------|---------------|
| **Configuration** | `GHIDRA_SERVER_PASSWORD` | `GHIDRA_SERVER_KEYSTORE` |
| **Storage** | Environment variable | File (Docker volume) |
| **Security** | Medium (env var exposed) | High (filesystem protected) |
| **Automation** | Pipe to stdin | Automatic |
| **Rotation** | Change env var | Replace key file |
| **Audit** | Limited | Full (server logs) |

## Code Changes

### Modified Files

1. **`ghidra_mcp_server_pyghidra.py`** (lines 140-220)
   - Removed `server_password` variable
   - Added `server_keystore` variable
   - Updated `HeadlessClientAuthenticator.installHeadlessClientAuthenticator()`
   - Added keystore validation and error handling

2. **`docker/entrypoint.pyghidra.sh`** (lines 27-90)
   - Added server mode validation
   - Added SSH keystore existence check
   - Added permission validation
   - Added environment variable exports

3. **New Configuration Files**
   - `examples/docker/ghidra-server/.env.pyghidra`
   - `examples/docker/ghidra-server/docker-compose.pyghidra.yml`

4. **New Documentation**
   - `docs/SSH_KEY_AUTHENTICATION.md` (Complete guide)
   - `examples/docker/ghidra-server/README.pyghidra.md` (Quick start)

5. **New Scripts**
   - `scripts/setup_ssh_auth.sh` (Automated setup)

## Error Handling

### New Error Messages

**Missing Keystore:**
```
ERROR: GHIDRA_SERVER_USER specified but GHIDRA_SERVER_KEYSTORE not set
SSH key authentication is required. Password authentication has been removed.
```

**Keystore Not Found:**
```
ERROR: SSH keystore file not found: /root/.ghidra/ssh_key
Please ensure the SSH private key is mounted via Docker volume.
```

**Wrong Permissions:**
```
WARNING: SSH keystore permissions are 777 (should be 600 or 400)
Attempting to fix permissions...
```

## Backward Compatibility

### ⚠️ Breaking Changes

1. **Password authentication no longer supported**
   - Old configurations using `GHIDRA_SERVER_PASSWORD` will fail
   - Must migrate to SSH key authentication

2. **New environment variable required**
   - `GHIDRA_SERVER_KEYSTORE` must be set for authenticated access
   - Volume mount required in Docker

3. **Dockerfile version**
   - Must use `Dockerfile.pyghidra` (Ghidra 12.0.3)
   - Old `Dockerfile` (Ghidra 11.0) not updated

### ✅ Still Compatible

1. **Anonymous access**
   - Still works without authentication
   - No configuration changes needed

2. **Local project mode**
   - Unchanged, not affected by this migration

3. **API endpoints**
   - No changes to HTTP API
   - Fully backward compatible

## Testing

### Verify Migration Success

```bash
# 1. Check container logs
docker logs ghidra-mcp-bridge-pyghidra-server

# Expected output:
# [PyGhidra-MCP-Bridge] Authentication: SSH key (/root/.ghidra/ssh_key)
# [PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed
# [PyGhidra-MCP-Bridge] ✓ Connected to server

# 2. Test API
curl http://localhost:8803/api/basic_info

# 3. Verify server connection
docker exec ghidra-mcp-bridge-pyghidra-server \
  python3 -c "import os; print(os.environ.get('GHIDRA_SERVER_KEYSTORE'))"
```

### Common Migration Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| **Old env vars** | `GHIDRA_SERVER_PASSWORD` still set | Remove from `.env`, use `.env.pyghidra` |
| **Wrong compose file** | Still using `docker-compose.yml` | Use `docker-compose.pyghidra.yml` |
| **Key not mounted** | `SSH keystore file not found` | Add volume mount in compose file |
| **Wrong permissions** | Permission warnings | Run `chmod 600 ~/.ghidra/bridge_key` |
| **Old Dockerfile** | Ghidra 11.0 | Use `Dockerfile.pyghidra` |

## Rollback Plan

If you need to rollback to password authentication:

1. **Checkout previous version:**
   ```bash
   git checkout HEAD~1
   ```

2. **Use standard Dockerfile:**
   ```bash
   cd examples/docker/ghidra-server
   docker-compose -f docker-compose.yml up -d
   ```

3. **Note:** Standard version uses Ghidra 11.0, not 12.0.3

## Future Plans

1. **PKI Certificate Support**
   - Add support for X.509 certificates
   - Enterprise PKI integration

2. **Multi-Key Support**
   - Support multiple keys per user
   - Key-based role assignment

3. **Key Rotation Automation**
   - Automatic key rotation scripts
   - Zero-downtime key updates

## References

- [SSH Key Authentication Guide](docs/SSH_KEY_AUTHENTICATION.md) - Complete setup guide
- [PyGhidra README](examples/docker/ghidra-server/README.pyghidra.md) - Quick start
- [Security Best Practices](docs/SSH_KEY_AUTHENTICATION.md#security-best-practices) - Production guidelines

## Support

For migration help:
1. Read [SSH_KEY_AUTHENTICATION.md](docs/SSH_KEY_AUTHENTICATION.md)
2. Check [Troubleshooting section](#testing)
3. Open an issue on GitHub

---

**Migration completed:** 2026-02-13
**Affected version:** PyGhidra mode only
**Standard mode:** Unchanged (still uses Ghidra 11.0)
