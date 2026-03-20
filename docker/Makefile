# Ghidra MCP Bridge
# Makefile for common Docker operations

.PHONY: help build up down logs shell test clean rebuild server-up server-down server-logs server-restart server-clean server-users server-add-user server-reset-password server-list-repos client-up client-down client-logs client-restart client2-up up-separated down-separated logs-separated help-separated check-env init-data info list-versions switch-version

# Load environment variables
-include .env
export

# Default target
help:
	@echo "Ghidra MCP Bridge (Version-Isolated Storage)"
	@echo ""
	@echo "Setup (First Time):"
	@echo "  cp .env.example .env    - Create config file"
	@echo "  vim .env                - Edit GHIDRA_DATA_DIR and GHIDRA_VERSION"
	@echo "  make info               - Verify configuration"
	@echo "  make init-data          - Initialize data directories"
	@echo ""
	@echo "Version Management:"
	@echo "  make info               - Show current configuration"
	@echo "  make list-versions      - List all available versions"
	@echo "  make switch-version     - Switch to different version"
	@echo ""
	@echo "Separated Server-Client Mode (AI + GUI collaboration):"
	@echo "  make up-separated       - Start server + client (one command) ⭐"
	@echo "  make server-up          - Start standalone Ghidra Server"
	@echo "  make client-up          - Start client (connects to server)"
	@echo "  make down-separated     - Stop all services"
	@echo "  make help-separated     - Detailed help for separated mode"
	@echo ""
	@echo "User Management:"
	@echo "  make server-users           - List all server users"
	@echo "  make server-add-user NAME=x - Add new user (password auth)"
	@echo "  make server-reset-password NAME=x - Reset user password"
	@echo "  make server-list-repos      - List repositories"
	@echo ""
	@echo "Development & Testing:"
	@echo "  make up-dev             - Start in development mode (with logs)"
	@echo "  make logs               - View Bridge logs (follow)"
	@echo "  make shell              - Access Bridge container shell"
	@echo "  make test               - Test API endpoints"
	@echo "  make reload             - Hot reload API modules"
	@echo "  make health             - Check container health"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean              - Remove containers and images"
	@echo "  make rebuild            - Clean + Build + Up"
	@echo ""

# ============================================
# Environment & Version Management
# ============================================

# Validate required variables
check-env:
	@if [ -z "$(GHIDRA_DATA_DIR)" ]; then \
		echo "ERROR: GHIDRA_DATA_DIR not set"; \
		echo ""; \
		echo "Please create .env file:"; \
		echo "  cp .env.example .env"; \
		echo "  # Edit .env and set GHIDRA_DATA_DIR"; \
		exit 1; \
	fi
	@if [ ! -d "$(GHIDRA_DATA_DIR)" ]; then \
		echo "ERROR: GHIDRA_DATA_DIR does not exist: $(GHIDRA_DATA_DIR)"; \
		echo ""; \
		echo "Creating directory..."; \
		mkdir -p "$(GHIDRA_DATA_DIR)"; \
		echo "✓ Created: $(GHIDRA_DATA_DIR)"; \
	fi

# Initialize data directory structure
init-data: check-env
	@echo "Initializing data directory for Ghidra $(GHIDRA_VERSION)..."
	@mkdir -p "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)"/{repos,config,ssh/clients}
	@mkdir -p "$(GHIDRA_DATA_DIR)/logs/$(GHIDRA_VERSION)"
	@echo "✓ Data directory initialized"
	@echo "  Location: $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/"

# Show current configuration
info: check-env
	@echo "========================================"
	@echo "  Ghidra MCP Bridge Configuration"
	@echo "========================================"
	@echo "Data Root:    $(GHIDRA_DATA_DIR)"
	@echo "Version:      $(GHIDRA_VERSION)"
	@echo "Server Port:  $(GHIDRA_SERVER_PORT)"
	@echo ""
	@echo "Data Location:"
	@echo "  Server Repos:    $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/repos"
	@echo "  Server Config:   $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/config"
	@echo "  SSH Keys:        $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/ssh/clients/"
	@echo "  Client Configs:  $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/client-config-<N>/"
	@echo "  Logs:            $(GHIDRA_DATA_DIR)/logs/$(GHIDRA_VERSION)"
	@echo ""
	@echo "Available versions:"
	@ls -d $(GHIDRA_DATA_DIR)/*/ 2>/dev/null | xargs -n1 basename || echo "  (none)"
	@echo ""

# List all versions
list-versions: check-env
	@echo "Available Ghidra versions in $(GHIDRA_DATA_DIR):"
	@ls -d $(GHIDRA_DATA_DIR)/*/ 2>/dev/null | xargs -n1 basename || echo "  (none)"

# Switch version
switch-version: check-env
	@echo "Current version: $(GHIDRA_VERSION)"
	@echo "Available versions:"
	@ls -d $(GHIDRA_DATA_DIR)/*/ 2>/dev/null | xargs -n1 basename || echo "  (none)"
	@echo ""
	@read -p "Enter version to switch to: " VERSION && \
	sed -i.bak "s/^GHIDRA_VERSION=.*/GHIDRA_VERSION=$$VERSION/" .env && \
	rm .env.bak && \
	echo "✓ Switched to version $$VERSION" && \
	echo "  Run 'make info' to verify"

# ============================================
# Build & Run
# ============================================

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
server-up: init-data
	@echo "Starting Ghidra Server..."
	@echo "  Version: $(GHIDRA_VERSION)"
	@echo "  Data:    $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/"
	@docker-compose -f docker-compose.server.yml up -d
	@echo ""
	@echo "✓ Server Started"
	@echo "  Port: $(GHIDRA_SERVER_PORT)"
	@echo "  SSH Keys: $(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/ssh/"
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
	@echo "  - SSH keys ($(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/ssh/clients/)"
	@echo "  - Client configs ($(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/client-config-*/)"
	@echo ""
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	@echo "Removing server data..."
	@docker-compose -f docker-compose.server.yml down -v
	@rm -rf "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/ssh/"
	@rm -rf "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)"/client-config-*/
	@echo "✓ Server data removed"

# Server user management
SVRADMIN_CMD = /opt/ghidra/server/svrAdmin

server-users:
	@echo "Ghidra Server users:"
	@docker exec ghidra-server-standalone $(SVRADMIN_CMD) -users 2>/dev/null || \
		echo "ERROR: Server container not running. Start with: make server-up"

server-add-user:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make server-add-user NAME=<username>"; \
		exit 1; \
	fi
	@echo "Adding user: $(NAME) (will prompt for password)"
	@docker exec -it ghidra-server-standalone $(SVRADMIN_CMD) -add $(NAME) --p

server-reset-password:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make server-reset-password NAME=<username>"; \
		exit 1; \
	fi
	@echo "Resetting password for: $(NAME)"
	@docker exec -it ghidra-server-standalone $(SVRADMIN_CMD) -reset $(NAME) --p

server-list-repos:
	@echo "Ghidra Server repositories:"
	@docker exec ghidra-server-standalone $(SVRADMIN_CMD) -list --users 2>/dev/null || \
		echo "ERROR: Server container not running. Start with: make server-up"

# ============================================
# Client Management
# ============================================

# Start client (connects to server)
client-up: check-env
	@echo "Starting Bridge Client..."
	@echo "  Version: $(GHIDRA_VERSION)"
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
client2-up: check-env
	@echo "Starting second Bridge Client..."
	@CLIENT_ID=2 \
	 CLIENT_MCP_PORT=8813 \
	 CLIENT_MCP_SSE_PORT=8814 \
	 docker-compose -f docker-compose.client.yml up -d
	@echo ""
	@echo "✓ Second Client Started (bridge-2)"
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
	@echo "User Management:"
	@echo "  make server-users           - List all users"
	@echo "  make server-add-user NAME=x - Add user (password auth)"
	@echo "  make server-reset-password NAME=x - Reset password"
	@echo "  make server-list-repos      - List repositories"
	@echo ""
	@echo "Client Management:"
	@echo "  make client-up      - Start client (ports 8803/8804)"
	@echo "  make client-down    - Stop client"
	@echo "  make client-logs    - View client logs"
	@echo "  make client-restart - Restart client"
	@echo "  make client2-up     - Start second client (ports 8813/8814)"
	@echo ""
	@echo "Multiple Clients:"
	@echo "  CLIENT_ID=3 \\"
	@echo "  CLIENT_MCP_PORT=8823 \\"
	@echo "  CLIENT_MCP_SSE_PORT=8824 \\"
	@echo "  docker-compose -f docker-compose.client.yml up -d"
	@echo ""
	@echo "Connect Ghidra GUI:"
	@echo "  1. File → New Project → Shared Project"
	@echo "  2. Server: localhost:$(GHIDRA_SERVER_PORT)"
	@echo "  3. User: root (password from server logs)"
	@echo "  4. Each client auto-registers as bridge-1, bridge-2, ..."
	@echo ""
