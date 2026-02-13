# MCP Client Configuration

This guide covers configuring MCP clients (Claude Desktop, Coco, etc.) to connect to Ghidra MCP Bridge.

## Overview

Ghidra MCP Bridge exposes MCP (Model Context Protocol) via **Server-Sent Events (SSE)** on port 8804 by default.

The MCP server provides the following tools:

- `ghidra_search` - Unified search (functions, symbols, strings, xrefs, etc.)
- `ghidra_view` - View decompiled/disassembled code
- `ghidra_list` - Browse symbols (ls-like interface)
- `ghidra_edit` - Edit operations (rename, datatype, comment)
- `ghidra_basic_info` - Get program basic information

## Connection URL

**SSE Mode (Recommended):**
```
http://localhost:8804/sse
```

**stdio Mode (for local debugging):**

See [`scripts/mcp_stdio.py`](../../scripts/mcp_stdio.py) for standalone stdio mode.

## Client Configuration

### Claude Desktop

#### macOS

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

#### Linux

Edit `~/.config/claude/settings.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

#### Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

### Coco (CopilotKit)

Add to your Coco configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse",
      "metadata": {
        "name": "Ghidra MCP Bridge",
        "description": "Ghidra reverse engineering capabilities",
        "version": "1.0.0"
      }
    }
  }
}
```

### Custom MCP Clients

For custom clients using the MCP SDK:

```python
from mcp import ClientSession, StdioServerParameters
import httpx

async def connect_to_ghidra():
    async with httpx.AsyncClient() as http_client:
        async with ClientSession(
            read_stream=...,  # SSE stream from http://localhost:8804/sse
            write_stream=...
        ) as session:
            # Initialize connection
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {tools}")

            # Call a tool
            result = await session.call_tool(
                "ghidra_search",
                arguments={"q": "main", "types": "functions"}
            )
            print(result)
```

## Docker Deployment

When running Ghidra MCP Bridge in Docker, ensure port 8804 is exposed:

```yaml
# docker-compose.yml
services:
  ghidra-bridge:
    ports:
      - "8803:8803"
      - "8804:8804"  # MCP SSE port
```

### Remote Access

For remote Docker deployments, update the URL:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://your-server-ip:8804/sse"
    }
  }
}
```

**Security note**: Consider using a reverse proxy with authentication for remote access.

## Verification

### Test MCP Connection

1. **Restart your MCP client** (Claude Desktop, Coco, etc.)

2. **Check for Ghidra tools** in the client UI:
   - Look for tools like `ghidra_search`, `ghidra_view`, etc.

3. **Test a simple query**:
   ```
   Use ghidra_search to find functions named "main"
   ```

### Check Bridge Logs

If connection fails, check the bridge logs:

**Local mode:**
```bash
# Check Ghidra console output
```

**Docker mode:**
```bash
docker logs ghidra-mcp-bridge
# Look for: "MCP SSE server started on http://0.0.0.0:8804"
```

### Test SSE Endpoint Directly

```bash
# Test SSE endpoint is accessible
curl -N http://localhost:8804/sse

# You should see SSE stream headers
```

## Troubleshooting

### Connection refused

**Symptom**: Client cannot connect to `http://localhost:8804/sse`

**Solutions**:

1. **Verify bridge is running:**
   ```bash
   curl http://localhost:8803/api/status
   ```

2. **Check MCP SSE server logs** for startup messages

3. **Verify port is not blocked** by firewall

4. **Check port mapping** (Docker):
   ```bash
   docker ps
   # Look for 0.0.0.0:8804->8804/tcp
   ```

### Tools not appearing in client

**Symptom**: MCP client connected, but no Ghidra tools available

**Solutions**:

1. **Check MCP server logs** for errors during tool registration

2. **Verify HTTP API is working:**
   ```bash
   curl http://localhost:8803/api/v1/search?q=main
   ```

3. **Restart the client** after configuration changes

### SSE stream timeout

**Symptom**: Connection drops after idle period

**Solution**: This is expected for SSE. The client should auto-reconnect. If not, check client reconnection settings.

### Permission errors

**Symptom**: Client connected, but tool calls fail with permission errors

**Solution**: Ensure Docker container has access to the Ghidra project (check volume mounts).

## stdio Mode (Advanced)

For local debugging, you can use stdio mode instead of SSE:

### Configuration

**Claude Desktop (stdio mode):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/python",
      "args": [
        "/path/to/Bridge/scripts/mcp_stdio.py",
        "--port", "8803"
      ]
    }
  }
}
```

### Advantages

- **Better debugging**: Can attach IDE debugger to Python process
- **No SSE overhead**: Direct stdio communication

### Disadvantages

- **Requires manual process management**: Bridge and stdio server run separately
- **More complex setup**: Need to ensure both processes are running

## Best Practices

1. **Use SSE mode for production** (auto-managed by bridge)
2. **Use stdio mode for development** (easier debugging)
3. **Secure remote access** with reverse proxy + auth
4. **Monitor connection health** via client logs
5. **Keep client configurations** in version control (without secrets)

## Next Steps

- Try the interactive examples: [`examples/api-usage/`](../../examples/api-usage/)
- Read the API reference: [`docs/api/api-reference.md`](../api/api-reference.md)
- Learn Docker deployment: [`docs/setup/docker-deployment.md`](docker-deployment.md)
