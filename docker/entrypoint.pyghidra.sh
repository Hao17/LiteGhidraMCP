#!/bin/bash
set -e

echo "==================================================="
echo "Ghidra MCP Bridge - PyGhidra Edition"
echo "==================================================="

# 1. Parse configuration
PROJECT_MODE="${PROJECT_MODE:-local}"
PROJECT_PATH="${PROJECT_PATH:-/ghidra-projects}"
PROJECT_NAME="${PROJECT_NAME:-default}"
GHIDRA_MCP_HOST="${GHIDRA_MCP_HOST:-0.0.0.0}"
GHIDRA_MCP_PORT="${GHIDRA_MCP_PORT:-8803}"
GHIDRA_MCP_SSE_PORT="${GHIDRA_MCP_SSE_PORT:-8804}"

echo "Ghidra Version: $(analyzeHeadless -help | head -1 | awk '{print $2}')"
echo "Python Version: $(python3 --version)"
echo "PyGhidra: $(python3 -c 'import pyghidra; print(pyghidra.__version__)' 2>/dev/null || echo 'installed')"
echo "---------------------------------------------------"
echo "Project Mode: $PROJECT_MODE"
echo "Project Path: $PROJECT_PATH"
echo "Project Name: $PROJECT_NAME"
echo "HTTP API: http://$GHIDRA_MCP_HOST:$GHIDRA_MCP_PORT"
echo "MCP SSE: http://$GHIDRA_MCP_HOST:$GHIDRA_MCP_SSE_PORT"
echo "==================================================="

# 2. Validate project (local mode)
if [ "$PROJECT_MODE" = "local" ]; then
    echo "Validating local project..."

    if [ ! -d "$PROJECT_PATH" ]; then
        echo "ERROR: Project directory does not exist: $PROJECT_PATH"
        echo "Please ensure the directory is mounted via Docker volume."
        exit 1
    fi

    # Check for .gpr file
    if [ ! -f "$PROJECT_PATH/$PROJECT_NAME.gpr" ]; then
        echo "WARNING: Project file not found: $PROJECT_PATH/$PROJECT_NAME.gpr"
        echo "PyGhidra will attempt to create/import the project automatically."
    else
        echo "✓ Found project file: $PROJECT_NAME.gpr"
    fi

    # Check for .rep directory
    if [ ! -d "$PROJECT_PATH/$PROJECT_NAME.rep" ]; then
        echo "WARNING: Project repository not found: $PROJECT_PATH/$PROJECT_NAME.rep"
        echo "PyGhidra will attempt to create the project automatically."
    else
        echo "✓ Found project repository: $PROJECT_NAME.rep/"
    fi
fi

# 3. Start MCP Bridge with PyGhidra
echo "---------------------------------------------------"
echo "Starting Ghidra MCP Bridge (PyGhidra mode)..."
echo "---------------------------------------------------"

# Export environment for Python script
export GHIDRA_INSTALL_DIR
export PROJECT_MODE
export PROJECT_PATH
export PROJECT_NAME
export GHIDRA_MCP_HOST
export GHIDRA_MCP_PORT
export GHIDRA_MCP_SSE_PORT
export LOG_LEVEL
export LOG_DIR

# Execute Python script with PyGhidra
exec python3 /app/ghidra_mcp_server_pyghidra.py
