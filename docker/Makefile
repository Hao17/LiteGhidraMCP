# Ghidra MCP Bridge
# Makefile for common Docker operations

.PHONY: help build up down logs shell test clean rebuild up-auto-server down-auto-server logs-auto-server init-server up-with-server down-with-server logs-server

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
	@echo "Server Mode (AI + GUI collaboration):"
	@echo "  up-with-server  - Start with auto-deployed Ghidra Server ⭐"
	@echo "  down-with-server - Stop all services including server"
	@echo "  logs-server     - View Ghidra Server logs"
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
# Ghidra Server Mode Targets
# ============================================

# Start with auto-deployed Ghidra Server
up-with-server up-auto-server:
	@echo "=================================================="
	@echo "  Starting Ghidra MCP Bridge + Ghidra Server"
	@echo "=================================================="
	@echo ""
	@echo "This will start:"
	@echo "  - Ghidra Server (blacktop/ghidra:12.0-server)"
	@echo "  - Server Initialization (creates user, repo, SSH keys)"
	@echo "  - Ghidra MCP Bridge (connected to server)"
	@echo ""
	docker-compose -f docker-compose.yml -f docker-compose.server.yml up -d
	@echo ""
	@echo "=================================================="
	@echo "  ✓ Services Started"
	@echo "=================================================="
	@echo ""
	@echo "Access:"
	@echo "  HTTP API:      http://localhost:8803"
	@echo "  MCP SSE:       http://localhost:8804/sse"
	@echo "  Ghidra Server: localhost:13100"
	@echo ""
	@echo "Server credentials (auto-configured):"
	@echo "  User:     bridge"
	@echo "  SSH Key:  ~/.ghidra/bridge_key"
	@echo "  Repo:     /mcp-projects"
	@echo ""
	@echo "Connect Ghidra GUI:"
	@echo "  File → New Project → Shared Project"
	@echo "  Server: localhost:13100"
	@echo "  User: bridge"
	@echo "  SSH Key: ~/.ghidra/bridge_key"
	@echo ""
	@echo "Commands:"
	@echo "  make logs-auto-server   - View all logs (Bridge + Server)"
	@echo "  make logs-server        - View Server logs only"
	@echo "  make test               - Test API"
	@echo "  make down-auto-server   - Stop all services"
	@echo ""

# Stop all services including server
down-with-server down-auto-server:
	@echo "Stopping all services (Bridge + Server)..."
	docker-compose -f docker-compose.yml -f docker-compose.server.yml down
	@echo "✓ All services stopped"
	@echo ""
	@echo "Note: Server data persists in Docker volumes:"
	@echo "  - ghidra-server-repos (repositories)"
	@echo "  - ghidra-server-config (configuration)"
	@echo "  - ~/.ghidra/bridge_key* (SSH keys)"
	@echo ""
	@echo "To remove volumes: docker-compose -f docker-compose.yml -f docker-compose.server.yml down -v"

# View all auto-server logs (Bridge + Server + Init)
logs-auto-server:
	@echo "All service logs (Ctrl+C to exit):"
	@echo ""
	docker-compose -f docker-compose.yml -f docker-compose.server.yml logs -f

# View Ghidra Server logs only
logs-server:
	@echo "Ghidra Server logs (Ctrl+C to exit):"
	@echo ""
	docker logs -f ghidra-server

# Manually trigger server initialization (if needed)
init-server:
	@echo "Manually triggering server initialization..."
	docker-compose -f docker-compose.yml -f docker-compose.server.yml up ghidra-server-init

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
