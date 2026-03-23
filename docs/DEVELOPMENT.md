# Development Guide

This guide covers local development workflow for Ghidra MCP Bridge.

## Development Workflow

### Hot Reload

After modifying API code, reload without restarting Ghidra:

```bash
curl http://127.0.0.1:8803/_reload
```

**What gets reloaded:**
- All modules in `api/`
- All modules in `api_v1/`
- Newly added `@route` decorated functions

**What does NOT get reloaded:**
- `ghidra_mcp_server.py` itself
- `utils/` modules (unless re-imported by API modules)
- Cached Ghidra state object

### Adding a New API

1. **Create a new module** in `api/`:

```python
# api/my_feature.py
from api import route

@route("/api/my_feature")
def my_function(state, param1="", limit=100):
    """
    My feature description.

    URL: GET /api/my_feature?param1=xxx&limit=50
    """
    prog = state.getCurrentProgram()
    # ... implementation
    return {"success": True, "data": ...}
```

2. **Trigger hot reload:**

```bash
curl http://127.0.0.1:8803/_reload
```

3. **Test your API:**

```bash
curl "http://127.0.0.1:8803/api/my_feature?param1=test&limit=10"
```

**No server restart required!**

### Debugging

#### Enable debug logging

Edit `utils/logging_config.py`:

```python
logging.basicConfig(
    level=logging.DEBUG,  # Change from INFO to DEBUG
    ...
)
```

#### Check Ghidra logs

**Console output**: Check Ghidra CodeBrowser console

**Log files**: Check Ghidra application logs
- macOS: `~/Library/Application Support/Ghidra/application.log`
- Linux: `~/.ghidra/application.log`
- Windows: `%USERPROFILE%\.ghidra\application.log`

## Common Issues

### Server won't start

1. **Check program is loaded** — a binary must be open in CodeBrowser
2. **Check port is not in use:** `lsof -i :8803`
3. **Check Python dependencies:** `pip list | grep mcp`

### Hot reload not working

1. **Check reload response:**
   ```bash
   curl http://127.0.0.1:8803/_reload
   # Should show: {"status": "reloaded", "modules": [...]}
   ```
2. Ensure your module is in `api/` or `api_v1/` with no syntax errors
3. Re-run `ghidra_mcp_server.py` in Script Manager if needed

### MCP SSE not working

1. Check subprocess: `ps aux | grep mcp_sse_proxy`
2. Check port: `curl -N http://127.0.0.1:8804/sse`
3. Check Ghidra console for SSE startup errors

### Jep threading errors

**Symptom**: `No Jep instance available on current thread`

**Causes**:
1. Java class name typo (case-sensitive!)
2. New Java imports in hot-reloaded modules

**Solutions**:

1. Fix class name (e.g. `TypeDef` not `Typedef`)
2. Use `sys.modules` caching for Java imports:
   ```python
   import sys
   _CACHE_KEY = '_my_module_java_class'
   if _CACHE_KEY not in sys.modules:
       from ghidra.some.package import JavaClass
       sys.modules[_CACHE_KEY] = JavaClass
   JavaClass = sys.modules[_CACHE_KEY]
   ```

See [CLAUDE.md](../CLAUDE.md) for details.

## Code Conventions

- **Indentation**: 4 spaces
- **Type hints**: Use where practical
- **Error handling**: Return `{"success": False, "error": "..."}` on errors

## IDE Setup

### VS Code

Recommended extensions: Python, Pylance

### PyCharm

1. Create Python interpreter with Ghidra's Python
2. Mark `api/` and `api_v1/` as source roots

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_HOST` | `127.0.0.1` | API server host |
| `GHIDRA_MCP_PORT` | `8803` | HTTP API port |
| `GHIDRA_MCP_SSE_PORT` | `8804` | MCP SSE port |
