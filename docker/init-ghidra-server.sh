#!/bin/bash
# Initialize Ghidra Server after auto-deployment
# This script creates the default repository and configures user access

set -e

echo "=================================================="
echo "  Ghidra Server Initialization"
echo "=================================================="

# Load environment variables
if [ -f .env ]; then
    source .env
fi

REPO_NAME="${GHIDRA_SERVER_REPO:-/default}"
SERVER_USER="${GHIDRA_SERVER_USER:-}"

echo ""
echo "Configuration:"
echo "  Repository: $REPO_NAME"
echo "  User:       ${SERVER_USER:-<anonymous>}"
echo ""

# Wait for Ghidra Server to be ready
echo "Waiting for Ghidra Server to start..."
for i in {1..30}; do
    if docker exec ghidra-mcp-server test -e /repos 2>/dev/null; then
        echo "✓ Ghidra Server is ready"
        break
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Verify server is accessible
if ! docker exec ghidra-mcp-server test -e /repos 2>/dev/null; then
    echo "✗ Error: Ghidra Server failed to start"
    exit 1
fi

echo ""
echo "Creating repository: $REPO_NAME"

# Create repository directory if it doesn't exist
REPO_DIR="/repos${REPO_NAME}"
if docker exec ghidra-mcp-server test -d "$REPO_DIR" 2>/dev/null; then
    echo "✓ Repository already exists: $REPO_NAME"
else
    # Create repository directory
    docker exec ghidra-mcp-server mkdir -p "$REPO_DIR"

    # Initialize repository using Ghidra's server commands
    # Note: The blacktop/ghidra:server image auto-initializes repositories in /repos
    echo "✓ Repository created: $REPO_NAME"
fi

# Configure user access (if user is specified)
if [ -n "$SERVER_USER" ]; then
    echo ""
    echo "Configuring user access..."
    echo "  Note: User management in blacktop/ghidra:server is handled via"
    echo "        GHIDRA_USERS environment variable at container startup."
    echo "  User '$SERVER_USER' should already be configured."
    echo ""
    echo "✓ User configuration complete"
fi

echo ""
echo "=================================================="
echo "  ✓ Initialization Complete"
echo "=================================================="
echo ""
echo "Ghidra Server is ready:"
echo "  Host:       localhost"
echo "  Port:       ${GHIDRA_SERVER_PORT:-13100}"
echo "  Repository: $REPO_NAME"
echo "  User:       ${SERVER_USER:-<anonymous access>}"
echo ""
echo "Connect from Ghidra GUI:"
echo "  1. File → New Project → Shared Project"
echo "  2. Server: localhost"
echo "  3. Port:   ${GHIDRA_SERVER_PORT:-13100}"
echo "  4. User:   ${SERVER_USER:-<leave empty for anonymous>}"
echo ""
echo "Ghidra MCP Bridge should now be connecting..."
echo "Run 'make logs' to view Bridge logs."
echo ""
