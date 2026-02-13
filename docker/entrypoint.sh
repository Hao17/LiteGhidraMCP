#!/bin/bash
set -e

echo "==================================================="
echo "Ghidra MCP Bridge - Docker Entrypoint"
echo "==================================================="

# 1. Parse configuration
PROJECT_MODE="${PROJECT_MODE:-local}"
PROJECT_PATH="${PROJECT_PATH:-/ghidra-projects}"
PROJECT_NAME="${PROJECT_NAME:-default}"
GHIDRA_MCP_HOST="${GHIDRA_MCP_HOST:-0.0.0.0}"
GHIDRA_MCP_PORT="${GHIDRA_MCP_PORT:-8803}"
GHIDRA_MCP_SSE_PORT="${GHIDRA_MCP_SSE_PORT:-8804}"

echo "Project Mode: $PROJECT_MODE"
echo "Project Path: $PROJECT_PATH"
echo "Project Name: $PROJECT_NAME"
echo "HTTP API: http://$GHIDRA_MCP_HOST:$GHIDRA_MCP_PORT"
echo "MCP SSE: http://$GHIDRA_MCP_HOST:$GHIDRA_MCP_SSE_PORT"
echo "==================================================="

# 2. Build analyzeHeadless command based on PROJECT_MODE
if [ "$PROJECT_MODE" = "server" ]; then
    # Ghidra Server mode
    GHIDRA_SERVER_HOST="${GHIDRA_SERVER_HOST:-localhost}"
    GHIDRA_SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    GHIDRA_SERVER_USER="${GHIDRA_SERVER_USER:-analyst}"
    GHIDRA_SERVER_REPO="${GHIDRA_SERVER_REPO:-/}"

    echo "Connecting to Ghidra Server: ${GHIDRA_SERVER_HOST}:${GHIDRA_SERVER_PORT}"
    echo "Repository: $GHIDRA_SERVER_REPO"
    echo "User: $GHIDRA_SERVER_USER"

    # Ghidra Server connection command
    # Note: Password is passed via environment variable or Docker secrets
    GHIDRA_CMD="analyzeHeadless \
        ghidra://${GHIDRA_SERVER_HOST}:${GHIDRA_SERVER_PORT}${GHIDRA_SERVER_REPO} \
        $PROJECT_NAME \
        -connect $GHIDRA_SERVER_USER \
        -scriptPath /app \
        -postScript ghidra_mcp_server.py"
else
    # Local filesystem mode
    echo "Using local project at: $PROJECT_PATH"

    # Check if project directory exists
    if [ ! -d "$PROJECT_PATH" ]; then
        echo "ERROR: Project directory does not exist: $PROJECT_PATH"
        echo "Please ensure the directory is mounted via Docker volume."
        exit 1
    fi

    # Local project command
    GHIDRA_CMD="analyzeHeadless \
        $PROJECT_PATH \
        $PROJECT_NAME \
        -scriptPath /app \
        -postScript ghidra_mcp_server.py"
fi

# 3. Start Ghidra headless + MCP Bridge
echo "Starting Ghidra headless..."
echo "Command: $GHIDRA_CMD"
echo "==================================================="

# Execute command and keep container running
# Note: analyzeHeadless in -postScript mode will keep running because MCP Bridge server is a daemon
exec $GHIDRA_CMD

# If script exits unexpectedly, capture error
echo "ERROR: Ghidra MCP Bridge exited unexpectedly"
exit 1
