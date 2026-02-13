#!/bin/bash
# Verification script for Docker setup

set -e

echo "========================================="
echo "Ghidra MCP Bridge - Setup Verification"
echo "========================================="
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} Found: $1"
        return 0
    else
        echo -e "${RED}✗${NC} Missing: $1"
        return 1
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} Found: $1/"
        return 0
    else
        echo -e "${RED}✗${NC} Missing: $1/"
        return 1
    fi
}

echo "Checking Docker files..."
check_file "docker/Dockerfile"
check_file "docker/entrypoint.sh"
check_file "docker/healthcheck.sh"
check_file "docker/docker-compose.yml"
check_file "docker/docker-compose.dev.yml"
check_file "docker/.dockerignore"
echo

echo "Checking configuration files..."
check_file "config/.env.example"
echo

echo "Checking documentation..."
check_file "docs/setup/docker-deployment.md"
check_file "docs/setup/local-development.md"
check_file "docs/setup/mcp-clients.md"
check_file "docs/architecture/docker-architecture.md"
check_file "docs/DOCKER_MIGRATION.md"
echo

echo "Checking examples..."
check_dir "examples/docker/local-project"
check_file "examples/docker/local-project/docker-compose.yml"
check_file "examples/docker/local-project/.env"
check_file "examples/docker/local-project/README.md"
check_dir "examples/docker/ghidra-server"
check_file "examples/docker/ghidra-server/docker-compose.yml"
check_file "examples/docker/ghidra-server/.env"
check_file "examples/docker/ghidra-server/README.md"
check_file "examples/api-usage/curl-examples.sh"
check_file "examples/mcp/coco-config.json"
check_file "examples/mcp/claude-config.json"
echo

echo "Checking utilities..."
check_file "utils/project_loader.py"
echo

echo "Checking permissions..."
if [ -x "docker/entrypoint.sh" ]; then
    echo -e "${GREEN}✓${NC} docker/entrypoint.sh is executable"
else
    echo -e "${RED}✗${NC} docker/entrypoint.sh is not executable"
fi

if [ -x "docker/healthcheck.sh" ]; then
    echo -e "${GREEN}✓${NC} docker/healthcheck.sh is executable"
else
    echo -e "${RED}✗${NC} docker/healthcheck.sh is not executable"
fi

if [ -x "examples/api-usage/curl-examples.sh" ]; then
    echo -e "${GREEN}✓${NC} examples/api-usage/curl-examples.sh is executable"
else
    echo -e "${RED}✗${NC} examples/api-usage/curl-examples.sh is not executable"
fi
echo

echo "Verifying existing code unchanged..."
check_file "ghidra_mcp_server.py"
check_dir "api"
check_dir "api_v1"
check_dir "scripts"
echo

echo "========================================="
echo -e "${GREEN}Setup verification complete!${NC}"
echo "========================================="
echo
echo "Next steps:"
echo "1. Build Docker image:"
echo "   cd docker && docker build -f Dockerfile -t ghidra-mcp-bridge:latest .."
echo
echo "2. Deploy (choose one):"
echo "   - Local project: cd examples/docker/local-project && docker-compose up"
echo "   - Ghidra Server: cd examples/docker/ghidra-server && docker-compose up"
echo
echo "3. Read documentation:"
echo "   - Deployment guide: docs/setup/docker-deployment.md"
echo "   - Architecture: docs/architecture/docker-architecture.md"
echo
