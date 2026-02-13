# Local Development Guide

This guide covers setting up Ghidra MCP Bridge for local development using Ghidra GUI.

## Prerequisites

1. **Ghidra** (11.0 or later) with **Ghidrathon** extension installed
2. **Python 3.9+** with required dependencies
3. **Ghidra project** created with binary loaded

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `mcp` - Model Context Protocol SDK
- `uvicorn` - ASGI server for MCP SSE
- `httpx` - HTTP client for MCP proxy

### 2. Set Up Ghidra Project

Create a Ghidra shared project:

1. Open Ghidra CodeBrowser
2. **File → New Project → Shared Project**
3. Choose project directory and name
4. Import your binary file

**Example structure**:
```
~/ghidra-projects/my_binary/
├── my_binary.gpr          # Project config
└── my_binary.rep/         # Project repository
    ├── idata/
    ├── user/
    └── versioned/
```

### 3. Add Bridge Scripts to Ghidra

**Option A: Copy to Ghidra scripts directory**

```bash
# Find Ghidra scripts directory (usually ~/ghidra_scripts/)
# Copy ghidra_mcp_server.py
cp ghidra_mcp_server.py ~/ghidra_scripts/
```

**Option B: Add Bridge directory to script paths**

In Ghidra:
1. **Window → Script Manager**
2. Click **"Manage Script Directories"** (folder icon)
3. Add Bridge project directory
4. Click **"Refresh"**

## Running the Server

### Quick Start

1. **Open your project** in Ghidra CodeBrowser
2. **Window → Script Manager**
3. Find and run **`ghidra_mcp_server.py`**

**Expected output** in Ghidra console:
```
[INFO] Cached Ghidra state: <GhidraState>
[INFO] Current program: my_binary
[INFO] Scanning API modules in: api/
[INFO] Registered route: /api/basic_info -> basic_info.get_basic_info
[INFO] Registered route: /api/search/functions -> search.search_functions
...
[INFO] Server started on http://127.0.0.1:8803
[INFO] MCP SSE server started on http://127.0.0.1:8804
```

### Verify Server

**Test HTTP API:**
```bash
curl http://127.0.0.1:8803/api/status
curl http://127.0.0.1:8803/api/basic_info
```

**Test MCP SSE:**
```bash
curl -N http://127.0.0.1:8804/sse
# Should see SSE stream headers
```

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

#### Use Python debugger

Add breakpoint in your API code:

```python
@route("/api/my_feature")
def my_function(state, param1=""):
    import pdb; pdb.set_trace()  # Debugger will pause here
    # ... your code
```

**Note**: Ghidra console may not support interactive debugger. Consider using logging instead.

#### Check Ghidra logs

**Console output**: Check Ghidra CodeBrowser console

**Log files**: Check Ghidra application logs
- macOS: `~/Library/Application Support/Ghidra/application.log`
- Linux: `~/.ghidra/application.log`
- Windows: `%USERPROFILE%\.ghidra\application.log`

## Testing

### Manual API Testing

Use the provided example script:

```bash
./examples/api-usage/curl-examples.sh
```

### MCP Testing

1. **Configure Claude Desktop** (see [`docs/setup/mcp-clients.md`](mcp-clients.md))

2. **Test with simple query:**
   ```
   Use ghidra_search to find all functions
   ```

### Automated Testing

Run test suite (if available):

```bash
pytest tests/
```

## Common Issues

### Server won't start

**Symptom**: Script exits immediately or shows error

**Solutions**:

1. **Check program is loaded:**
   ```python
   # Verify in Ghidra Script Manager
   currentProgram = state.getCurrentProgram()
   if currentProgram is None:
       print("ERROR: No program loaded!")
   ```

2. **Check port is not in use:**
   ```bash
   lsof -i :8803
   # If occupied, kill the process or change GHIDRA_MCP_PORT
   ```

3. **Check Python dependencies:**
   ```bash
   pip list | grep mcp
   # Should show: mcp, uvicorn, httpx
   ```

### Hot reload not working

**Symptom**: Code changes not reflected after `/_reload`

**Solutions**:

1. **Check reload response:**
   ```bash
   curl http://127.0.0.1:8803/_reload
   # Should show: {"status": "reloaded", "modules": [...]}
   ```

2. **Verify module imports:**
   - Ensure your module is in `api/` or `api_v1/`
   - Check for Python syntax errors

3. **Restart server if needed:**
   - Re-run `ghidra_mcp_server.py` in Script Manager

### MCP SSE not working

**Symptom**: MCP clients can't connect

**Solutions**:

1. **Check subprocess started:**
   ```bash
   ps aux | grep mcp_sse_proxy
   ```

2. **Check port 8804 accessible:**
   ```bash
   curl -N http://127.0.0.1:8804/sse
   ```

3. **Check logs** in Ghidra console for SSE startup errors

### Jep threading errors

**Symptom**: `No Jep instance available on current thread`

**Causes**:
1. Java class name typo (case-sensitive!)
2. New Java imports in hot-reloaded modules

**Solutions**:

1. **Fix class name typo:**
   ```python
   # Wrong: from ghidra.program.model.data import Typedef
   # Right: from ghidra.program.model.data import TypeDef
   ```

2. **Use sys.modules caching** for Java imports:
   ```python
   import sys
   _CACHE_KEY = '_my_module_java_class'
   if _CACHE_KEY not in sys.modules:
       from ghidra.some.package import JavaClass
       sys.modules[_CACHE_KEY] = JavaClass
   JavaClass = sys.modules[_CACHE_KEY]
   ```

See [CLAUDE.md](../../CLAUDE.md) section "Jep Threading Errors" for details.

## Code Conventions

Follow existing patterns in the codebase:

- **Indentation**: 4 spaces
- **Type hints**: Use where practical
- **Docstrings**: Document all public functions
- **Error handling**: Return `{"success": False, "error": "..."}` on errors

**Example API function:**

```python
from api import route
from typing import Optional

@route("/api/my_feature")
def my_function(state, query: str = "", limit: int = 100) -> dict:
    """
    Brief description of what this function does.

    Args:
        state: Ghidra GhidraState object
        query: Search query string
        limit: Maximum results to return

    Returns:
        dict: {"success": bool, "data": ..., "error": ...}
    """
    try:
        prog = state.getCurrentProgram()
        if prog is None:
            return {"success": False, "error": "No program loaded"}

        # Implementation...
        results = []

        return {
            "success": True,
            "data": results,
            "total": len(results)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
```

## IDE Setup

### VS Code

Recommended extensions:
- Python
- Pylance
- Ghidra Python (unofficial)

**settings.json:**
```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true
}
```

### PyCharm

1. Create Python interpreter with Ghidra's Python
2. Mark `api/` and `api_v1/` as source roots
3. Enable type checking

## Environment Variables

Local development uses these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_HOST` | `127.0.0.1` | API server host |
| `GHIDRA_MCP_PORT` | `8803` | HTTP API port |
| `GHIDRA_MCP_SSE_PORT` | `8804` | MCP SSE port |

Set in shell before running Ghidra:

```bash
export GHIDRA_MCP_PORT=9000
# Then start Ghidra and run the script
```

## Next Steps

- Deploy to Docker: [`docs/setup/docker-deployment.md`](docker-deployment.md)
- Configure MCP clients: [`docs/setup/mcp-clients.md`](mcp-clients.md)
- Read API documentation: [`docs/api/api-reference.md`](../api/api-reference.md)
- Explore examples: [`examples/`](../../examples/)
