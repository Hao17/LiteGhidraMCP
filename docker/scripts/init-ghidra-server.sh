#!/bin/bash
set -e

SSH_DIR="/root/.ghidra"
SSH_KEY="${SSH_DIR}/bridge_key"
SERVER_HOST="${GHIDRA_SERVER_HOST:-ghidra-server}"
SERVER_PORT="${GHIDRA_SERVER_PORT:-13100}"
REPO_NAME="${AUTO_SERVER_REPO:-/mcp-projects}"
USER_NAME="${AUTO_SERVER_USER:-bridge}"

echo "=== Ghidra Server Initialization ==="

# 1. Generate SSH keys if not present
if [ ! -f "${SSH_KEY}" ]; then
    echo "Generating SSH key pair..."
    mkdir -p "${SSH_DIR}"
    ssh-keygen -t rsa -b 4096 -f "${SSH_KEY}" -N "" -C "ghidra-bridge-auto"
    chmod 600 "${SSH_KEY}"
    chmod 644 "${SSH_KEY}.pub"
    echo "✓ SSH keys generated"
else
    echo "✓ SSH keys already exist"
fi

# 2. Wait for server to be ready
echo "Waiting for Ghidra Server..."
for i in {1..60}; do
    if nc -z "${SERVER_HOST}" "${SERVER_PORT}"; then
        echo "✓ Server is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "✗ Server timeout"
        exit 1
    fi
    sleep 1
done

# 3. Configure server via docker exec
echo "Configuring server..."

# Add user
echo "Adding user: ${USER_NAME}"
docker exec ghidra-server /ghidra/server/svrAdmin -add "${USER_NAME}" 2>&1 | grep -v "already exists" || true

# Install public key
echo "Installing SSH public key..."
PUB_KEY=$(cat "${SSH_KEY}.pub")
docker exec ghidra-server sh -c "mkdir -p /repos/.users/${USER_NAME} && echo '${PUB_KEY}' >> /repos/.users/${USER_NAME}/authorized_keys"

# Create repository
echo "Creating repository: ${REPO_NAME}"
docker exec ghidra-server /ghidra/server/svrAdmin -create "${REPO_NAME}" 2>&1 | grep -v "already exists" || true

# Grant access
echo "Granting repository access..."
docker exec ghidra-server /ghidra/server/svrAdmin -grant "${REPO_NAME}" "${USER_NAME}"

echo "✓ Server initialized successfully"
echo "  User: ${USER_NAME}"
echo "  Repo: ${REPO_NAME}"
echo "  SSH Key: ${SSH_KEY}"
echo ""
echo "To connect from Ghidra GUI:"
echo "  1. File → New Project → Shared Project"
echo "  2. Server: localhost:${SERVER_PORT}"
echo "  3. User: ${USER_NAME}"
echo "  4. SSH Key: ${SSH_KEY}"
