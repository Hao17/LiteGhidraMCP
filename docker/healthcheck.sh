#!/bin/bash
# Health check: verify HTTP API is responding

GHIDRA_MCP_PORT="${GHIDRA_MCP_PORT:-8803}"

# Try to access the /api/status endpoint
if curl -f -s "http://localhost:${GHIDRA_MCP_PORT}/api/status" > /dev/null 2>&1; then
    echo "Health check passed"
    exit 0
else
    echo "Health check failed: API not responding"
    exit 1
fi
