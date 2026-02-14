#!/bin/bash
set -e

echo "==================================================="
echo "Ghidra MCP Bridge"
echo "==================================================="

# 0. Determine run mode (SERVER or CLIENT)
RUN_MODE="${RUN_MODE:-CLIENT}"
echo "Run Mode: ${RUN_MODE}"
echo "==================================================="

# Handle SERVER mode separately
if [ "$RUN_MODE" = "SERVER" ]; then
    echo "Starting Ghidra Server..."

    # Server configuration
    SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    SERVER_DIR="/repos"
    MAXMEM="${MAXMEM:-4G}"

    # Create server directory structure
    mkdir -p "${SERVER_DIR}"

    echo "Server configuration:"
    echo "  Port: ${SERVER_PORT}"
    echo "  Repository: ${SERVER_DIR}"
    echo "  Max Memory: ${MAXMEM}"
    echo "  Ghidra: ${GHIDRA_INSTALL_DIR}"
    echo "==================================================="

    # Navigate to Ghidra server directory
    cd "${GHIDRA_INSTALL_DIR}/server"

    # Start Ghidra Server in console mode (foreground)
    exec ./ghidraSvr console \
        -ip 0.0.0.0 \
        -p "${SERVER_PORT}" \
        -d "${SERVER_DIR}" \
        -e0 \
        -a2 \
        -u
fi

# CLIENT mode continues below...

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

# 2. Handle auto-server mode (before validation)
if [ "$PROJECT_MODE" = "auto-server" ]; then
    echo "Auto-Server mode detected"
    echo "Waiting for Ghidra Server to initialize..."

    # Wait for server to be ready (max 120s for initialization)
    for i in {1..120}; do
        if nc -z ${GHIDRA_SERVER_HOST:-ghidra-server} ${GHIDRA_SERVER_PORT:-13100}; then
            echo "✓ Ghidra Server is ready"
            break
        fi
        if [ $i -eq 120 ]; then
            echo "✗ Ghidra Server timeout - initialization took too long"
            echo "Check server logs: docker logs ghidra-server"
            exit 1
        fi
        sleep 1
    done

    # Set server connection variables
    export GHIDRA_SERVER_HOST="${GHIDRA_SERVER_HOST:-ghidra-server}"
    export GHIDRA_SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    export GHIDRA_SERVER_USER="${AUTO_SERVER_USER:-bridge}"
    export GHIDRA_SERVER_REPO="${AUTO_SERVER_REPO:-/mcp-projects}"
    export GHIDRA_SERVER_KEYSTORE="/root/.ghidra/ssh_key"

    echo "✓ Auto-server configuration:"
    echo "  Server: ${GHIDRA_SERVER_HOST}:${GHIDRA_SERVER_PORT}"
    echo "  User: ${GHIDRA_SERVER_USER}"
    echo "  Repository: ${GHIDRA_SERVER_REPO}"
    echo "  SSH Key: ${GHIDRA_SERVER_KEYSTORE}"

    # Override PROJECT_MODE to "server" for the Python script
    export PROJECT_MODE="server"
fi

# 3. Validate configuration based on mode
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

elif [ "$PROJECT_MODE" = "server" ]; then
    echo "Validating Ghidra Server configuration..."

    GHIDRA_SERVER_HOST="${GHIDRA_SERVER_HOST:-localhost}"
    GHIDRA_SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    GHIDRA_SERVER_USER="${GHIDRA_SERVER_USER}"
    GHIDRA_SERVER_KEYSTORE="${GHIDRA_SERVER_KEYSTORE}"
    GHIDRA_SERVER_REPO="${GHIDRA_SERVER_REPO:-}"

    echo "Server: ${GHIDRA_SERVER_HOST}:${GHIDRA_SERVER_PORT}"
    echo "User: ${GHIDRA_SERVER_USER:-'(anonymous)'}"
    echo "Repository: ${GHIDRA_SERVER_REPO:-'(auto-detect)'}"

    # Validate SSH key authentication
    if [ -n "$GHIDRA_SERVER_USER" ]; then
        if [ -z "$GHIDRA_SERVER_KEYSTORE" ]; then
            echo "ERROR: GHIDRA_SERVER_USER specified but GHIDRA_SERVER_KEYSTORE not set"
            echo "SSH key authentication is required. Password authentication has been removed."
            exit 1
        fi

        if [ ! -f "$GHIDRA_SERVER_KEYSTORE" ]; then
            echo "ERROR: SSH keystore file not found: $GHIDRA_SERVER_KEYSTORE"
            echo "Please ensure the SSH private key is mounted via Docker volume."
            exit 1
        fi

        echo "✓ SSH keystore found: $GHIDRA_SERVER_KEYSTORE"

        # Check keystore permissions (should be 600 or 400)
        KEYSTORE_PERMS=$(stat -f %A "$GHIDRA_SERVER_KEYSTORE" 2>/dev/null || stat -c %a "$GHIDRA_SERVER_KEYSTORE" 2>/dev/null)
        if [ "$KEYSTORE_PERMS" != "600" ] && [ "$KEYSTORE_PERMS" != "400" ]; then
            echo "WARNING: SSH keystore permissions are $KEYSTORE_PERMS (should be 600 or 400)"
            echo "Attempting to fix permissions..."
            chmod 600 "$GHIDRA_SERVER_KEYSTORE" || echo "WARNING: Failed to change permissions"
        fi
    else
        echo "⚠ No user specified, using anonymous access"
    fi

    # Export server configuration for Python script
    export GHIDRA_SERVER_HOST
    export GHIDRA_SERVER_PORT
    export GHIDRA_SERVER_USER
    export GHIDRA_SERVER_KEYSTORE
    export GHIDRA_SERVER_REPO
fi

# 4. Start MCP Bridge
echo "---------------------------------------------------"
echo "Starting Ghidra MCP Bridge..."
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

# Execute Python script
exec python3 /app/ghidra_mcp_server_pyghidra.py
