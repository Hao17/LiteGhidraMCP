#!/bin/bash
# Quick setup script for SSH key authentication with Ghidra Server

set -e

echo "========================================"
echo "Ghidra Server SSH Authentication Setup"
echo "========================================"
echo ""

# Configuration
GHIDRA_DIR="$HOME/.ghidra"
KEY_NAME="bridge_key"
KEY_PATH="$GHIDRA_DIR/$KEY_NAME"
SERVER_USER="${1:-bridge}"

echo "Configuration:"
echo "  User: $SERVER_USER"
echo "  Key directory: $GHIDRA_DIR"
echo "  Key name: $KEY_NAME"
echo ""

# Step 1: Create .ghidra directory
echo "[1/5] Creating .ghidra directory..."
if [ -d "$GHIDRA_DIR" ]; then
    echo "  ✓ Directory already exists: $GHIDRA_DIR"
else
    mkdir -p "$GHIDRA_DIR"
    echo "  ✓ Created directory: $GHIDRA_DIR"
fi
echo ""

# Step 2: Generate SSH key pair
echo "[2/5] Generating SSH key pair..."
if [ -f "$KEY_PATH" ]; then
    echo "  ⚠ SSH key already exists: $KEY_PATH"
    read -p "  Overwrite existing key? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "  Skipping key generation"
    else
        echo "  Generating new key..."
        ssh-keygen -t rsa -b 4096 -f "$KEY_PATH" -N "" -C "ghidra-server-$SERVER_USER"
        echo "  ✓ New SSH key generated"
    fi
else
    echo "  Generating SSH key..."
    ssh-keygen -t rsa -b 4096 -f "$KEY_PATH" -N "" -C "ghidra-server-$SERVER_USER"
    echo "  ✓ SSH key generated successfully"
fi
echo ""

# Step 3: Set correct permissions
echo "[3/5] Setting file permissions..."
chmod 600 "$KEY_PATH"
chmod 644 "$KEY_PATH.pub"
echo "  ✓ Private key: 600 (read-write for owner only)"
echo "  ✓ Public key: 644 (read for all)"
echo ""

# Step 4: Display public key
echo "[4/5] Your SSH public key:"
echo "========================================="
cat "$KEY_PATH.pub"
echo "========================================="
echo ""

# Step 5: Instructions for Ghidra Server
echo "[5/5] Next steps:"
echo ""
echo "1. Add the public key to Ghidra Server:"
echo "   a) Copy the public key above"
echo "   b) On Ghidra Server machine, run:"
echo "      cd /path/to/ghidra/server"
echo "      ./svrAdmin"
echo "   c) In svrAdmin console:"
echo "      > add user $SERVER_USER"
echo "      > set ssh-key $SERVER_USER <paste-public-key-here>"
echo ""
echo "2. Update Docker configuration:"
echo "   a) Edit examples/docker/ghidra-server/.env.pyghidra:"
echo "      GHIDRA_SERVER_USER=$SERVER_USER"
echo "      GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key"
echo ""
echo "   b) Edit docker-compose.pyghidra.yml volumes:"
echo "      - $KEY_PATH:/root/.ghidra/ssh_key:ro"
echo ""
echo "3. Test the connection:"
echo "   cd examples/docker/ghidra-server"
echo "   docker-compose -f docker-compose.pyghidra.yml up -d"
echo "   docker logs -f ghidra-mcp-bridge-pyghidra-server"
echo ""
echo "========================================="
echo "Setup complete!"
echo ""
echo "SSH Key Summary:"
echo "  Private key: $KEY_PATH"
echo "  Public key:  $KEY_PATH.pub"
echo "  User:        $SERVER_USER"
echo ""
echo "For detailed instructions, see:"
echo "  docs/SSH_KEY_AUTHENTICATION.md"
echo "========================================="
