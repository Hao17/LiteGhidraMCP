#!/bin/bash
# Verification script for the current Docker layout.

set -u

echo "========================================="
echo "Ghidra MCP Bridge - Setup Verification"
echo "========================================="
echo

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

failures=0

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} Found: $1"
    else
        echo -e "${RED}✗${NC} Missing: $1"
        failures=$((failures + 1))
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} Found: $1/"
    else
        echo -e "${RED}✗${NC} Missing: $1/"
        failures=$((failures + 1))
    fi
}

check_exec() {
    if [ -x "$1" ]; then
        echo -e "${GREEN}✓${NC} Executable: $1"
    else
        echo -e "${RED}✗${NC} Not executable: $1"
        failures=$((failures + 1))
    fi
}

echo "Checking Docker files..."
check_file "docker/Dockerfile"
check_file "docker/entrypoint.sh"
check_file "docker/healthcheck.sh"
check_file "docker/docker-compose.yml"
check_file "docker/docker-compose.dev.yml"
check_file "docker/docker-compose.server.yml"
check_file "docker/docker-compose.client.yml"
check_file "docker/.env.example"
check_file "docker/.env.server.example"
check_file "docker/.env.client.example"
check_file "docker/.env.auto-server.example"
check_file "docker/Makefile"
check_file "docker/QUICKSTART.md"
check_file "docker/ARCHITECTURE.md"
check_file "docker/server.conf"
check_file "docker/.dockerignore"
echo

echo "Checking documentation..."
check_file "README.md"
check_file "README_ZH.md"
check_file "docs/DEVELOPMENT.md"
check_file "docs/SSH_KEY_AUTHENTICATION.md"
check_file "docs/SSH_KEY_TESTING.md"
echo

echo "Checking examples..."
check_file "examples/api-usage/curl-examples.sh"
check_file "examples/mcp/coco-config.json"
check_file "examples/mcp/claude-config.json"
echo

echo "Checking runtime sources..."
check_file "ghidra_mcp_server.py"
check_file "ghidra_mcp_server_pyghidra.py"
check_dir "api"
check_dir "api_v1"
check_dir "scripts"
check_dir "utils"
echo

echo "Checking permissions..."
check_exec "docker/entrypoint.sh"
check_exec "docker/healthcheck.sh"
check_exec "examples/api-usage/curl-examples.sh"
echo

echo "Checking script syntax..."
if bash -n "docker/entrypoint.sh"; then
    echo -e "${GREEN}✓${NC} bash -n docker/entrypoint.sh"
else
    echo -e "${RED}✗${NC} bash -n docker/entrypoint.sh"
    failures=$((failures + 1))
fi

if bash -n "docker/healthcheck.sh"; then
    echo -e "${GREEN}✓${NC} bash -n docker/healthcheck.sh"
else
    echo -e "${RED}✗${NC} bash -n docker/healthcheck.sh"
    failures=$((failures + 1))
fi
echo

echo "========================================="
if [ "$failures" -eq 0 ]; then
    echo -e "${GREEN}Setup verification passed!${NC}"
else
    echo -e "${RED}Setup verification failed: ${failures} issue(s) found${NC}"
fi
echo "========================================="
echo
echo "Next steps:"
echo "1. Configure Docker:"
echo "   cd docker && cp .env.example .env"
echo
echo "2. Start separated server-client mode:"
echo "   cd docker && make server-up"
echo "   cd docker && make client N=1 REPO=test"
echo
echo "3. Read the current docs:"
echo "   - Quick start: docker/QUICKSTART.md"
echo "   - Architecture: docker/ARCHITECTURE.md"
echo "   - SSH keys: docs/SSH_KEY_AUTHENTICATION.md"
echo

if [ "$failures" -ne 0 ]; then
    exit 1
fi
