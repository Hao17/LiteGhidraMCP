# Ghidra MCP Bridge
# Makefile for common Docker operations

.PHONY: help build up down logs shell test clean rebuild server-up server-down server-logs server-restart server-clean client-up client-down client-logs client-restart client2-up up-separated down-separated logs-separated help-separated

# Default target
help:
	@echo "Ghidra MCP Bridge (PyGhidra)"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "Local Project Mode (default):"
	@echo "  build           - Build Docker image"
	@echo "  up              - Start services (local project)"
	@echo "  down            - Stop services"
	@echo ""
	@echo "Separated Server-Client Mode (AI + GUI collaboration):"
	@echo "  up-separated    - Start server + client (one command) ⭐"
	@echo "  server-up       - Start standalone Ghidra Server"
	@echo "  client-up       - Start client (connects to server)"
	@echo "  down-separated  - Stop all services"
	@echo "  help-separated  - Detailed help for separated mode"
	@echo ""
	@echo "Development & Testing:"
	@echo "  up-dev          - Start in development mode (with logs)"
	@echo "  logs            - View Bridge logs (follow)"
	@echo "  shell           - Access Bridge container shell"
	@echo "  test            - Test API endpoints"
	@echo "  reload          - Hot reload API modules"
	@echo "  health          - Check container health"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean           - Remove containers and images"
	@echo "  rebuild         - Clean + Build + Up"
	@echo ""
	@echo "Configuration:"
	@echo "  Edit .env file or set environment variables:"
	@echo "    HOST_PROJECT_PATH=/path/to/project"
	@echo "    PROJECT_NAME=my_binary"

# Build Docker image
build:
	@echo "Building Docker image..."
	docker-compose build

# Start services (production)
up:
	@echo "Starting Ghidra MCP Bridge..."
	docker-compose up -d
	@echo ""
	@echo "✓ Services started"
	@echo "  HTTP API: http://localhost:8803"
	@echo "  MCP SSE:  http://localhost:8804/sse"
	@echo ""
	@echo "Run 'make logs' to view logs"
	@echo "Run 'make test' to test API"

# Start in development mode
up-dev:
	@echo "Starting in development mode (hot-reload enabled)..."
	docker-compose -f docker-compose.dev.yml up

# Stop services
down:
	@echo "Stopping services..."
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Access container shell
shell:
	docker exec -it ghidra-mcp-bridge /bin/bash

# Test API endpoints
test:
	@echo "Testing API endpoints..."
	@echo ""
	@echo "1. Status:"
	@curl -s http://localhost:8803/api/status | jq -C '.'
	@echo ""
	@echo "2. Basic Info:"
	@curl -s http://localhost:8803/api/basic_info | jq -C '.program.name, .program.functions.total_count'
	@echo ""
	@echo "3. Search functions (main):"
	@curl -s "http://localhost:8803/api/search/functions?q=main&limit=5" | jq -C '.results[] | .name'
	@echo ""

# Hot reload API modules
reload:
	@echo "Reloading API modules..."
	@curl -s http://localhost:8803/_reload | jq -C '.'

# Check health
health:
	@echo "Container health status:"
	@docker inspect ghidra-mcp-bridge | jq -C '.[0].State.Health'

# Clean up
clean:
	@echo "Removing containers and images..."
	docker-compose down -v
	docker rmi ghidra-mcp-bridge 2>/dev/null || true
	@echo "✓ Cleaned"

# Rebuild everything
rebuild: clean build up
	@echo "✓ Rebuild complete"

# ============================================
# Separated Server-Client Mode Targets
# ============================================

# Quick start - Start both server and client with one command
up-separated:
	@echo "=================================================="
	@echo "  Starting Separated Server + Client"
	@echo "=================================================="
	@echo ""
	@$(MAKE) server-up
	@echo ""
	@echo "Waiting for server initialization..."
	@sleep 8
	@echo ""
	@$(MAKE) client-up
	@echo ""
	@echo "=================================================="
	@echo "  ✓ Server + Client Started"
	@echo "=================================================="
	@echo ""
	@echo "Access:"
	@echo "  HTTP API:      http://localhost:8803"
	@echo "  MCP SSE:       http://localhost:8804/sse"
	@echo "  Ghidra Server: localhost:13100"
	@echo ""
	@echo "Commands:"
	@echo "  make logs-separated - View all logs"
	@echo "  make test           - Test API"
	@echo "  make down-separated - Stop all services"
	@echo ""

# Stop all services (server + client)
down-separated:
	@echo "Stopping all services..."
	@docker-compose -f docker-compose.client.yml down 2>/dev/null || true
	@docker-compose -f docker-compose.server.yml down
	@echo "✓ All services stopped"

# View all logs (server + client)
logs-separated:
	@echo "All service logs (Ctrl+C to exit):"
	@echo ""
	@echo "Use: docker logs <container> -f  to view individual logs"
	@echo ""
	@docker logs ghidra-server-standalone -f &
	@docker logs ghidra-mcp-bridge-client-1 -f

# ============================================
# Server Management
# ============================================

# Start standalone Ghidra Server
server-up:
	@echo "Starting Ghidra Server..."
	@docker-compose -f docker-compose.server.yml up -d
	@echo ""
	@echo "✓ Server Started"
	@echo "  Port: 13100"
	@echo "  SSH Keys: ./server-data/ssh/"
	@echo ""
	@echo "Run 'make server-logs' to view logs"

# Stop Ghidra Server
server-down:
	@echo "Stopping Ghidra Server..."
	@docker-compose -f docker-compose.server.yml down
	@echo "✓ Server stopped"

# View server logs
server-logs:
	@echo "Server logs (Ctrl+C to exit):"
	@echo ""
	@docker logs ghidra-server-standalone -f

# Restart server
server-restart:
	@$(MAKE) server-down
	@$(MAKE) server-up

# Clean server data (WARNING: destructive!)
server-clean:
	@echo "⚠️  WARNING: This will remove all server data!"
	@echo "  - Docker volumes (repos + config)"
	@echo "  - SSH keys (./server-data/ssh/)"
	@echo ""
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	@echo "Removing server data..."
	@docker-compose -f docker-compose.server.yml down -v
	@rm -rf ./server-data/ssh/
	@echo "✓ Server data removed"

# ============================================
# Client Management
# ============================================

# Start client (connects to server)
client-up:
	@echo "Starting Bridge Client..."
	@docker-compose -f docker-compose.client.yml up -d
	@echo ""
	@echo "✓ Client Started"
	@echo "  HTTP API: http://localhost:8803"
	@echo "  MCP SSE:  http://localhost:8804/sse"
	@echo ""
	@echo "Run 'make client-logs' to view logs"

# Stop client
client-down:
	@echo "Stopping Bridge Client..."
	@docker-compose -f docker-compose.client.yml down
	@echo "✓ Client stopped"

# View client logs
client-logs:
	@echo "Client logs (Ctrl+C to exit):"
	@echo ""
	@docker logs ghidra-mcp-bridge-client-1 -f

# Restart client
client-restart:
	@$(MAKE) client-down
	@$(MAKE) client-up

# Start second client on different ports (for testing multi-client)
client2-up:
	@echo "Starting second Bridge Client..."
	@CLIENT_CONTAINER_NAME=ghidra-mcp-bridge-client-2 \
	 CLIENT_MCP_PORT=8813 \
	 CLIENT_MCP_SSE_PORT=8814 \
	 CLIENT_LOG_DIR=./logs/client-2 \
	 docker-compose -f docker-compose.client.yml up -d
	@echo ""
	@echo "✓ Second Client Started"
	@echo "  HTTP API: http://localhost:8813"
	@echo "  MCP SSE:  http://localhost:8814/sse"

# ============================================
# Separated Mode Help
# ============================================

help-separated:
	@echo "=================================================="
	@echo "  Separated Server-Client Architecture"
	@echo "=================================================="
	@echo ""
	@echo "Quick Start:"
	@echo "  make up-separated   - Start server + client (one command)"
	@echo "  make down-separated - Stop all services"
	@echo ""
	@echo "Server Management:"
	@echo "  make server-up      - Start standalone server"
	@echo "  make server-down    - Stop server"
	@echo "  make server-logs    - View server logs"
	@echo "  make server-restart - Restart server"
	@echo "  make server-clean   - Remove all server data (⚠️ destructive)"
	@echo ""
	@echo "Client Management:"
	@echo "  make client-up      - Start client (ports 8803/8804)"
	@echo "  make client-down    - Stop client"
	@echo "  make client-logs    - View client logs"
	@echo "  make client-restart - Restart client"
	@echo "  make client2-up     - Start second client (ports 8813/8814)"
	@echo ""
	@echo "Multiple Clients:"
	@echo "  CLIENT_CONTAINER_NAME=ghidra-mcp-bridge-client-3 \\"
	@echo "  CLIENT_MCP_PORT=8823 \\"
	@echo "  CLIENT_MCP_SSE_PORT=8824 \\"
	@echo "  CLIENT_LOG_DIR=./logs/client-3 \\"
	@echo "  docker-compose -f docker-compose.client.yml up -d"
	@echo ""
	@echo "Connect Ghidra GUI:"
	@echo "  1. File → New Project → Shared Project"
	@echo "  2. Server: localhost:13100"
	@echo "  3. User: bridge"
	@echo "  4. PKI Authentication → ./server-data/ssh/bridge_key"
	@echo ""

# Check configuration
check-env:
	@echo "Current configuration:"
	@echo "  HOST_PROJECT_PATH: $${HOST_PROJECT_PATH:-<not set>}"
	@echo "  PROJECT_NAME:      $${PROJECT_NAME:-default}"
	@echo ""
	@if [ -f .env ]; then \
		echo "Environment file (.env) found:"; \
		cat .env | grep -v '^#' | grep -v '^$$'; \
	else \
		echo "⚠ No .env file found. Copy .env.example to .env"; \
	fi
