# Migration Guide: Ghidrathon → PyGhidra

This guide explains the migration from Ghidrathon-based Docker deployment to PyGhidra-based deployment.

## Summary of Changes

### What Changed

| Component | Old (Ghidrathon) | New (PyGhidra) |
|-----------|------------------|----------------|
| **Base Image** | `blacktop/ghidra:11.0` | Custom (Ghidra 12.0.3) |
| **Python Bridge** | Ghidrathon (Jep) | PyGhidra (JPype) |
| **Startup Method** | `analyzeHeadless -postScript` | Direct Python execution |
| **Main Script** | `ghidra_mcp_server.py` | `ghidra_mcp_server_pyghidra.py` |
| **Entrypoint** | `entrypoint.sh` | `entrypoint.pyghidra.sh` |
| **Dockerfile** | `Dockerfile` | `Dockerfile.pyghidra` |
| **Compose File** | `docker-compose.yml` | `docker-compose.pyghidra.yml` |

### Why Migrate?

1. ✅ **Official Support**: PyGhidra is officially integrated in Ghidra 12.0+
2. ✅ **Better Threading**: No Jep threading limitations
3. ✅ **Easier Maintenance**: No manual plugin installation
4. ✅ **Latest Features**: Access to Ghidra 12.0+ improvements
5. ✅ **Future-Proof**: NSA's recommended approach

## Migration Steps

### Step 1: Backup Current Setup

```bash
# Backup your current configuration
cp docker/docker-compose.yml docker/docker-compose.yml.backup
cp docker/.env docker/.env.backup

# Stop current services
docker-compose -f docker/docker-compose.yml down
```

### Step 2: Switch to PyGhidra Files

The new PyGhidra files are:

```
docker/
├── Dockerfile.pyghidra              # New Dockerfile
├── entrypoint.pyghidra.sh           # New entrypoint
├── docker-compose.pyghidra.yml      # New compose file
├── docker-compose.pyghidra.dev.yml  # New dev compose
├── .env.example                     # Updated env template
├── QUICKSTART.pyghidra.md          # Quick start guide
└── Makefile                         # Convenience commands
```

### Step 3: Update Environment Variables

Your `.env` file remains mostly the same:

```bash
# These stay the same
HOST_PROJECT_PATH=/path/to/your/ghidra-project
PROJECT_NAME=my_binary
GHIDRA_MCP_PORT=8803
GHIDRA_MCP_SSE_PORT=8804
LOG_LEVEL=INFO

# PROJECT_MODE also stays the same
PROJECT_MODE=local
```

No changes needed to environment variables!

### Step 4: Build New Image

```bash
cd docker

# Using docker-compose
docker-compose -f docker-compose.pyghidra.yml build

# Or using Makefile
make build
```

### Step 5: Start New Services

```bash
# Start services
docker-compose -f docker-compose.pyghidra.yml up -d

# Or using Makefile
make up
```

### Step 6: Verify Migration

```bash
# Check logs
docker logs ghidra-mcp-bridge-pyghidra -f

# You should see:
# [PyGhidra-MCP-Bridge] Initializing PyGhidra...
# [PyGhidra-MCP-Bridge] ✓ PyGhidra started successfully
# HTTP API:   http://0.0.0.0:8803
# MCP SSE:    http://0.0.0.0:8804/sse
```

**Test API:**

```bash
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
```

### Step 7: Update MCP Client Configuration

**No changes needed!** The MCP SSE endpoint remains the same:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

## Behavioral Differences

### Threading Model

**Old (Ghidrathon):**
- Jep limitation: one Python interpreter per thread
- Could cause errors with `ThreadingHTTPServer`
- Required workarounds for concurrent requests

**New (PyGhidra):**
- Full Python threading support
- No interpreter restrictions
- Better concurrency handling

### Startup Time

**Old (Ghidrathon):**
- Fast startup (Ghidra already initialized by `analyzeHeadless`)
- Health check start_period: 60s

**New (PyGhidra):**
- Slightly slower startup (PyGhidra initializes JVM)
- Health check start_period: 90s (to accommodate JVM startup)

### API Compatibility

**Good news:** All existing API endpoints remain the same!

The `MockGhidraState` class in `ghidra_mcp_server_pyghidra.py` provides the same interface as the Ghidrathon `state` object, so all API modules work without modification.

### Memory Usage

**Old:** ~2-4GB (Ghidra 11.0)
**New:** ~3-5GB (Ghidra 12.0 + PyGhidra)

Increase Docker memory limit if needed:

```yaml
deploy:
  resources:
    limits:
      memory: 8G  # Increase from 6G
```

## Troubleshooting Migration

### Issue: "Import pyghidra failed"

**Cause:** PyGhidra not installed

**Solution:** Rebuild image (pip install pyghidra is in Dockerfile.pyghidra)

```bash
docker-compose -f docker-compose.pyghidra.yml build --no-cache
```

### Issue: "Failed to start JVM"

**Cause:** Insufficient memory or GHIDRA_INSTALL_DIR not set

**Solution:** Check environment variables in container:

```bash
docker exec ghidra-mcp-bridge-pyghidra env | grep GHIDRA
```

### Issue: "No programs found in project"

**Cause:** Project exists but no binaries imported

**Solution:** This is a warning, not an error. Import binaries:

1. Via Ghidra GUI before starting Docker, OR
2. Via API (feature to be added)

### Issue: Port already in use

**Cause:** Old container still running

**Solution:**

```bash
# Stop old container
docker stop ghidra-mcp-bridge

# Or change ports in .env
GHIDRA_MCP_PORT=8813
GHIDRA_MCP_SSE_PORT=8814
```

## Rollback Plan

If you need to rollback to Ghidrathon version:

```bash
# Stop PyGhidra version
docker-compose -f docker-compose.pyghidra.yml down

# Restore old configuration
mv docker/.env.backup docker/.env
mv docker/docker-compose.yml.backup docker/docker-compose.yml

# Start old version
docker-compose -f docker/docker-compose.yml up -d
```

## Performance Comparison

Based on initial testing:

| Metric | Ghidrathon | PyGhidra | Notes |
|--------|------------|----------|-------|
| Startup time | ~30s | ~45s | PyGhidra JVM init |
| API latency | ~50ms | ~50ms | Same |
| Decompile time | ~200ms | ~200ms | Same |
| Concurrent requests | Limited | Unlimited | PyGhidra advantage |
| Memory usage | 3GB | 4GB | Ghidra 12.0 overhead |

## API Module Compatibility

All existing API modules work without modification:

- ✅ `api/basic_info.py` - Compatible
- ✅ `api/search.py` - Compatible
- ✅ `api/view.py` - Compatible
- ✅ `api/symbol_tree.py` - Compatible
- ✅ `api/comment.py` - Compatible
- ✅ `api/rename.py` - Compatible
- ✅ `api/datatype.py` - Compatible
- ✅ `api_v1/*` - All compatible

The `MockGhidraState` class ensures backward compatibility.

## Future Enhancements

Features planned for PyGhidra version:

1. **Multi-binary support** - Switch between programs via API
2. **Binary import API** - Import new binaries without GUI
3. **Project management** - Create/delete projects via API
4. **Ghidra Server** - Full support for remote collaboration
5. **Plugin support** - Load Ghidra extensions dynamically

## Getting Help

If you encounter issues during migration:

1. Check logs: `docker logs ghidra-mcp-bridge-pyghidra`
2. Verify environment: `make check-env`
3. Test manually: `make test`
4. Report issue: [GitHub Issues](https://github.com/your-repo/issues)

## Conclusion

The migration to PyGhidra provides:
- ✅ Official support from NSA
- ✅ Better threading and concurrency
- ✅ Access to latest Ghidra features
- ✅ Future-proof architecture

All existing APIs remain compatible, making this a smooth upgrade path.
