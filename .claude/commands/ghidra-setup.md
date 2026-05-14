# Ghidra MCP Setup

Set up the Ghidra MCP Bridge for binary analysis in this project. Run when you need to reverse-engineer a native binary (`.so`, ELF, PE, etc.) and the Bridge isn't connected yet.

## Arguments
- `$ARGUMENTS` — Optional: path to the binary file to analyze (e.g., `./libs/libfoo.so`)

## Quick path (if Bridge is already running)

```
ghidra_overview()
```

If this MCP tool exists and returns a binary name + sane function count, you're already connected — skip straight to `/ghidra` and analyze. Otherwise, work through the steps below.

## Workflow

### Step 1: Check prerequisites

```bash
which gmcp && gmcp --version
```

If `gmcp` is not found, install it from the Bridge repo (one time per machine):
```bash
pip install -e /path/to/Bridge   # adjust to wherever you cloned the Bridge
```

If this is the first time using the Bridge in *this* project, also install the skill so your AI client has the same usage doc:
```bash
gmcp install -d . skill claude-code   # or: codex / cursor / copilot
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

To analyze multiple binaries simultaneously, give each its own client (1–9):

```bash
gmcp client start 1 -r myrepo -b binary_a -f ./binary_a.so
gmcp client start 2 -r myrepo -b binary_b -f ./binary_b.so
gmcp install mcp claude-code --client 1   # → MCP name "ghidra"   on port 8804
gmcp install mcp claude-code --client 2   # → MCP name "ghidra-2" on port 8814
```

Port and MCP-name table:

| Client | HTTP  | SSE   | Default MCP name |
|--------|-------|-------|------------------|
| 1      | 8803  | 8804  | `ghidra`         |
| 2      | 8813  | 8814  | `ghidra-2`       |
| 3      | 8823  | 8824  | `ghidra-3`       |
| N      | `8803 + (N-1)*10` | `8804 + (N-1)*10` | `ghidra-N` |

In your AI session, Client 1's tools are `ghidra_overview`, `ghidra_search`, etc; Client 2's tools are `ghidra-2_overview`, `ghidra-2_search`, etc. Use the prefix to pick which binary to talk to. `gmcp status` shows which client holds which binary.

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
