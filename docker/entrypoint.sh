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
    GHIDRA_IP="${GHIDRA_IP:-0.0.0.0}"
    SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    REPO_DIR="/repos"
    SSH_DIR="/ssh"
    SERVER_REPO="${SERVER_REPO_NAME:-/mcp-projects}"
    SVRADMIN="${GHIDRA_INSTALL_DIR}/server/svrAdmin"

    echo "Server configuration:"
    echo "  IP: ${GHIDRA_IP}"
    echo "  Port: ${SERVER_PORT}"
    echo "  Repository: ${REPO_DIR}"
    echo "  Repo: ${SERVER_REPO}"
    echo "  Ghidra: ${GHIDRA_INSTALL_DIR}"
    echo "==================================================="

    # Create repository directory
    mkdir -p "${REPO_DIR}/~admin"

    # 1. Ensure clients directory exists for per-client SSH keys
    mkdir -p "${SSH_DIR}/clients"

    # 2. Write adm.cmd to add root user (only if not already registered)
    ADM_CMD=""
    if ! grep -q "^root$" "${REPO_DIR}/.users/users" 2>/dev/null; then
        echo "Will add user: root"
        ADM_CMD="-add root"
    else
        echo "User root already registered"
    fi
    if [ -n "${ADM_CMD}" ]; then
        echo "${ADM_CMD}" > "${REPO_DIR}/~admin/adm.cmd"
    fi

    # Generate random password for root user
    ROOT_PASS=$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)

    # 3. Background post-init: wait for server to be ready, set root password, scan for client keys
    (
        echo "[post-init] Waiting for server to listen on port ${SERVER_PORT}..."
        for i in $(seq 1 60); do
            if nc -z localhost "${SERVER_PORT}" 2>/dev/null; then
                echo "[post-init] Server is ready (after ${i}s)"
                break
            fi
            if [ "$i" -eq 60 ]; then
                echo "[post-init] ERROR: Server did not start within 60s"
                exit 1
            fi
            sleep 1
        done

        # Set root user password via svrAdmin
        echo "[post-init] Setting root user password..."
        if printf '%s\n%s\n' "${ROOT_PASS}" "${ROOT_PASS}" | "${SVRADMIN}" -reset root --p 2>/dev/null; then
            echo "[post-init] Root password set successfully"
        else
            echo "[post-init] WARNING: Failed to set root password (user may not exist yet)"
        fi

        echo "=================================================="
        echo "  Server Ready"
        echo ""
        echo "  Users:"
        echo "    root (password): ${ROOT_PASS}"
        echo ""
        echo "  Client users auto-registered from:"
        echo "    /ssh/clients/<name>/ssh_key.pub"
        echo "=================================================="

        # Continuously scan for client public keys (runs as long as server is alive)
        # Ghidra Server stores SSH public keys in /repos/~ssh/<username>.pub
        SSH_PUBKEY_DIR="${REPO_DIR}/~ssh"
        mkdir -p "${SSH_PUBKEY_DIR}"

        echo "[post-init] Starting client key scanner..."
        while true; do
            for pubkey in "${SSH_DIR}"/clients/*/ssh_key.pub; do
                [ -f "$pubkey" ] || continue
                username=$(basename "$(dirname "$pubkey")")
                dest="${SSH_PUBKEY_DIR}/${username}.pub"

                # Skip if already installed with current key
                if [ -f "$dest" ] && cmp -s "$pubkey" "$dest"; then
                    continue
                fi

                # Install public key to ~ssh directory
                cp "$pubkey" "$dest"
                echo "[post-init] Installed SSH key for: ${username}"

                # Add user if not already registered
                if ! grep -q "^${username}$" "${REPO_DIR}/.users/users" 2>/dev/null; then
                    "${SVRADMIN}" -add "${username}" 2>/dev/null
                    echo "[post-init] Registered user: ${username}"

                    # Grant access to all existing repos
                    for repo_dir in "${REPO_DIR}"/*/; do
                        [ -d "$repo_dir" ] || continue
                        repo_name=$(basename "$repo_dir")
                        # Skip admin/system directories
                        [[ "$repo_name" == ~* || "$repo_name" == .* ]] && continue
                        "${SVRADMIN}" -grant "${username}" +a "${repo_name}" 2>/dev/null || true
                    done
                fi
            done

            # Full ACL sync: ensure all users have access to all repos
            # (handles repos created after user registration)
            for repo_dir in "${REPO_DIR}"/*/; do
                [ -d "$repo_dir" ] || continue
                repo_name=$(basename "$repo_dir")
                [[ "$repo_name" == ~* || "$repo_name" == .* ]] && continue
                for pubkey in "${SSH_DIR}"/clients/*/ssh_key.pub; do
                    [ -f "$pubkey" ] || continue
                    username=$(basename "$(dirname "$pubkey")")
                    "${SVRADMIN}" -grant "${username}" +a "${repo_name}" 2>/dev/null || true
                done
            done

            sleep 5
        done
    ) &

    # Navigate to Ghidra server directory and start
    cd "${GHIDRA_INSTALL_DIR}/server"
    exec env GHIDRA_IP="${GHIDRA_IP}" ./ghidraSvr console
fi

# CLIENT mode continues below...

# 1. Parse configuration
PROJECT_MODE="${PROJECT_MODE:-}"
if [ -z "$PROJECT_MODE" ]; then
    echo "ERROR: PROJECT_MODE not set."
    echo "  Use PROJECT_MODE=auto-server (recommended) or PROJECT_MODE=local"
    exit 1
fi
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

    # Determine client identity
    CLIENT_USER="${AUTO_SERVER_USER:-bridge-${CLIENT_ID:-1}}"
    SSH_CLIENT_DIR="/ssh/clients/${CLIENT_USER}"

    # Generate SSH key pair if not present
    if [ ! -f "${SSH_CLIENT_DIR}/ssh_key" ]; then
        echo "Generating SSH key pair for ${CLIENT_USER}..."
        mkdir -p "${SSH_CLIENT_DIR}"
        ssh-keygen -t rsa -b 4096 -m PEM -f "${SSH_CLIENT_DIR}/ssh_key" -N "" -C "${CLIENT_USER}"
        chmod 600 "${SSH_CLIENT_DIR}/ssh_key"
        chmod 644 "${SSH_CLIENT_DIR}/ssh_key.pub"
        echo "SSH keys generated: ${SSH_CLIENT_DIR}/ssh_key"
    else
        echo "SSH keys exist: ${SSH_CLIENT_DIR}/ssh_key"
    fi

    echo "Waiting for Ghidra Server to initialize..."

    # Wait for server to be ready (max 120s for initialization)
    for i in $(seq 1 120); do
        if nc -z ${GHIDRA_SERVER_HOST:-ghidra-server} ${GHIDRA_SERVER_PORT:-13100} 2>/dev/null; then
            echo "Ghidra Server is ready (after ${i}s)"
            break
        fi
        if [ "$i" -eq 120 ]; then
            echo "Ghidra Server timeout - initialization took too long"
            echo "Check server logs: docker logs ghidra-server"
            exit 1
        fi
        sleep 1
    done

    # Wait for server to register our user (server scans every 1s)
    echo "Waiting for server to register user ${CLIENT_USER}..."
    sleep 5

    # Set server connection variables
    export GHIDRA_SERVER_HOST="${GHIDRA_SERVER_HOST:-ghidra-server}"
    export GHIDRA_SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
    export GHIDRA_SERVER_USER="${CLIENT_USER}"
    export GHIDRA_SERVER_REPO="${AUTO_SERVER_REPO:-/mcp-projects}"
    export GHIDRA_SERVER_KEYSTORE="${SSH_CLIENT_DIR}/ssh_key"

    echo "Auto-server configuration:"
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
        echo "Found project file: $PROJECT_NAME.gpr"
    fi

    # Check for .rep directory
    if [ ! -d "$PROJECT_PATH/$PROJECT_NAME.rep" ]; then
        echo "WARNING: Project repository not found: $PROJECT_PATH/$PROJECT_NAME.rep"
        echo "PyGhidra will attempt to create the project automatically."
    else
        echo "Found project repository: $PROJECT_NAME.rep/"
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

        echo "SSH keystore found: $GHIDRA_SERVER_KEYSTORE"

        # Check keystore permissions (should be 600 or 400)
        KEYSTORE_PERMS=$(stat -c %a "$GHIDRA_SERVER_KEYSTORE" 2>/dev/null || stat -f %A "$GHIDRA_SERVER_KEYSTORE" 2>/dev/null)
        if [ "$KEYSTORE_PERMS" != "600" ] && [ "$KEYSTORE_PERMS" != "400" ]; then
            echo "WARNING: SSH keystore permissions are $KEYSTORE_PERMS (should be 600 or 400)"
            echo "Attempting to fix permissions..."
            chmod 600 "$GHIDRA_SERVER_KEYSTORE" || echo "WARNING: Failed to change permissions"
        fi
    else
        echo "No user specified, using anonymous access"
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
