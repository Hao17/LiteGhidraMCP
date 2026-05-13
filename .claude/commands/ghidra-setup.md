# Ghidra MCP Setup

Start a Ghidra Docker environment, load a binary, connect MCP, and begin analysis. Use this when you need to reverse-engineer a native binary (.so, ELF, PE, etc.) with Ghidra.

## Arguments
- `$ARGUMENTS` — Optional: path to the binary file to analyze (e.g., `./libs/libfoo.so`)

## Workflow

### Step 1: Check prerequisites

```bash
which gmcp && gmcp --version
```

If `gmcp` is not found, install it:
```bash
pip install -e ~/Repos/Onmi/OnmiPy/Bridge
```

### Step 2: Check current state

```bash
gmcp status --json
```

- If server is running and a client already has the target binary loaded → skip to Step 5 (MCP connection)
- If server is running but no client has the target binary → go to Step 4 (start client)
- If nothing is running → go to Step 3 (start server)

### Step 3: Start server (if not running)

```bash
gmcp server up
```

Wait for the server to be ready:
```bash
gmcp status
```

### Step 4: Start client with binary

There are two scenarios:

**Scenario A — Binary file on host (first time, needs import):**
```bash
gmcp client start 1 -r <repo_name> -b <binary_name> -f <path_to_binary_file>
```

Example:
```bash
gmcp client start 1 -r baobao -b libmsaoaidsec.so -f ./libs/libmsaoaidsec.so
```

**Scenario B — Binary already imported in repo:**
```bash
gmcp client start 1 -r <repo_name> -b <binary_name>
```

**One-command shortcut (server + client 1):**
```bash
gmcp up -r <repo_name> -b <binary_name> -f <path_to_binary_file>
```

Wait for analysis to complete (check logs):
```bash
gmcp client logs 1
```

Look for "HTTP Server: http://..." in the logs to confirm the client is ready.

### Step 5: Configure MCP connection

```bash
gmcp install mcp claude-code --client 1
```

This registers the MCP server with Claude Code. For multiple clients:
```bash
gmcp install mcp claude-code --client 2   # Client 2 → ghidra-2 on port 8814
```

Verify the connection works by using the MCP tool:
```
ghidra_overview()
```

If this returns binary metadata, the setup is complete. Proceed with `/ghidra` for analysis.

### Step 6: Begin analysis

Use `/ghidra` to start the analysis workflow, or directly call:
```
ghidra_overview()
```

## Multi-binary Setup

To analyze multiple binaries simultaneously:
```bash
gmcp client start 1 -r myrepo -b binary_a -f ./binary_a.so
gmcp client start 2 -r myrepo -b binary_b -f ./binary_b.so
gmcp install mcp claude-code --client 1   # → ghidra on port 8804
gmcp install mcp claude-code --client 2   # → ghidra-2 on port 8814
```

Client N uses ports: HTTP `880N3`, SSE `880N4` (e.g., Client 2 → 8813/8814).

## Teardown

```bash
gmcp client stop 1      # Stop one client
gmcp down               # Stop everything (server + all clients)
```

## Troubleshooting

```bash
gmcp status --json      # Check what's running
gmcp client logs 1      # Check client logs
gmcp troubleshoot check # Diagnose issues
gmcp troubleshoot fix   # Auto-fix common problems
```

## gmcp CLI Quick Reference

```bash
gmcp info                   # Show config
gmcp build                  # Build Docker image
gmcp status                 # Show running services

gmcp up -r REPO -b BIN [-f FILE]     # Start server + client 1
gmcp down                             # Stop all

gmcp server up / down / restart / logs
gmcp client start N -r REPO -b BIN [-f FILE]
gmcp client stop N / logs N

gmcp install mcp claude-code [--client N]
```
