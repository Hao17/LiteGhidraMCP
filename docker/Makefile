# Ghidra MCP Bridge
# Makefile for common Docker operations

.PHONY: help build up down logs shell test clean rebuild server-up server-down server-logs server-restart server-clean server-users server-add-user server-reset-password server-list-repos client client-stop client-logs client-up client-down client-restart client2-up client2-down up-separated down-separated logs-separated help-separated check-env check-repo check-n init-data info list-versions switch-version troubleshoot troubleshoot-fix

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
	@echo "  make server-up          - Start standalone Ghidra Server"
	@echo "  make client N=<1-9> REPO=<name> [BINARY=<name-or-path>] [BINARY_FILE=<path>]"
	@echo "                          - Start client N (ports auto-calculated) ⭐"
	@echo "  make client-stop N=<1-9>  - Stop client N"
	@echo "  make client-logs N=<1-9>  - View client N logs"
	@echo "  make down-separated     - Stop all services"
	@echo "  make help-separated     - Detailed help for separated mode"
	@echo ""
	@echo "User Management:"
	@echo "  make server-users           - List all server users"
	@echo "  make server-add-user NAME=x - Add new user (password auth)"
	@echo "  make server-reset-password NAME=x - Reset user password"
	@echo "  make server-list-repos      - List repositories"
	@echo ""
	@echo "Troubleshoot:"
	@echo "  make troubleshoot       - Diagnose problems (checkout locks, unhealthy clients, ...)"
	@echo "  make troubleshoot-fix   - Auto-fix detected problems"
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

# Validate REPO parameter
check-repo:
	@if [ -z "$(REPO)" ]; then \
		echo "ERROR: REPO is required."; \
		echo "Usage: make client N=<1-9> REPO=<name> [BINARY=<name-or-path>] [BINARY_FILE=<path>]"; \
		exit 1; \
	fi

# Validate N parameter (client instance number, default 1)
N ?= 1
check-n:
	@if [ "$(N)" -lt 1 ] 2>/dev/null || [ "$(N)" -gt 9 ] 2>/dev/null; then \
		echo "ERROR: N must be between 1 and 9 (got: $(N))"; \
		exit 1; \
	fi

# Initialize data directory structure
init-data: check-env
	@echo "Initializing data directory for Ghidra $(GHIDRA_VERSION)..."
	@mkdir -p "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)"/{repos,config,ssh/clients,imports}
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
up-separated: check-repo
	@echo "=================================================="
	@echo "  Starting Separated Server + Client"
	@echo "=================================================="
	@echo ""
	@$(MAKE) server-up
	@echo ""
	@$(MAKE) client-up REPO=$(REPO) BINARY=$(BINARY) BINARY_FILE=$(BINARY_FILE)
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

# Stop all services (server + all clients 1-9)
down-separated:
	@echo "Stopping all services..."
	@for i in 1 2 3 4 5 6 7 8 9; do \
		docker-compose -p ghidra-client-$$i -f docker-compose.client.yml down 2>/dev/null || true; \
	done
	@docker-compose -f docker-compose.server.yml down
	@echo "✓ All services stopped"

# View all logs (server + clients)
logs-separated:
	@echo "All service logs (Ctrl+C to exit):"
	@echo ""
	@echo "Individual logs:"
	@echo "  make server-logs  - Server logs"
	@echo "  make client-logs  - Client 1 logs"
	@echo ""
	@docker logs ghidra-server-standalone -f &
	@docker-compose -p ghidra-client-1 -f docker-compose.client.yml logs -f 2>/dev/null || \
	 docker logs ghidra-mcp-bridge-client-1 -f

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
# Client Management (Generic)
# ============================================

# Port calculation: N=1→8803/8804, N=2→8813/8814, N=3→8823/8824, ...
# HTTP = 8800 + (N-1)*10 + 3,  SSE = HTTP + 1
_CLIENT_HTTP_PORT = $(shell echo $$((8800 + ($(N) - 1) * 10 + 3)))
_CLIENT_SSE_PORT  = $(shell echo $$((8800 + ($(N) - 1) * 10 + 4)))

# Generic: start client N
# Usage: make client N=3 REPO=aweme BINARY=38.1.0/all_init.o [BINARY_FILE=path]
client: check-env check-repo check-n
	@if [ -n "$(BINARY_FILE)" ]; then \
		mkdir -p "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/imports"; \
		cp "$(BINARY_FILE)" "$(GHIDRA_DATA_DIR)/$(GHIDRA_VERSION)/imports/$(or $(BINARY),$(notdir $(BINARY_FILE)))"; \
		echo "Binary staged: $(BINARY_FILE)"; \
	fi
	@CLIENT_ID=$(N) CLIENT_MCP_PORT=$(_CLIENT_HTTP_PORT) CLIENT_MCP_SSE_PORT=$(_CLIENT_SSE_PORT) \
	 GHIDRA_SERVER_REPO=/$(REPO) \
	 PROGRAM_NAME=$(BINARY) \
	 IMPORT_BINARY_NAME=$(if $(BINARY_FILE),$(or $(BINARY),$(notdir $(BINARY_FILE))),) \
	 docker-compose -p ghidra-client-$(N) -f docker-compose.client.yml up -d
	@echo ""
	@echo "✓ Client $(N) started"
	@echo "  Repo:    $(REPO)"
	@echo "  Binary:  $(or $(BINARY),(first available))"
	@echo "  HTTP:    http://localhost:$(_CLIENT_HTTP_PORT)"
	@echo "  MCP SSE: http://localhost:$(_CLIENT_SSE_PORT)/sse"
	@echo ""
	@echo "Run 'make client-logs N=$(N)' to view logs"

# Generic: stop client N
# Usage: make client-stop N=3
client-stop: check-n
	@docker-compose -p ghidra-client-$(N) -f docker-compose.client.yml down 2>/dev/null || true
	@echo "✓ Client $(N) stopped"

# Generic: view client N logs
# Usage: make client-logs N=3
client-logs: check-n
	@echo "Client $(N) logs (Ctrl+C to exit):"
	@echo ""
	@docker logs ghidra-mcp-bridge-client-$(N) -f 2>/dev/null || \
	 docker-compose -p ghidra-client-$(N) -f docker-compose.client.yml logs -f

# ---- Aliases for backward compatibility ----

client-up: check-env check-repo
	@$(MAKE) client N=1 REPO=$(REPO) BINARY=$(BINARY) BINARY_FILE=$(BINARY_FILE)

client-down:
	@$(MAKE) client-stop N=1

client-restart:
	@$(MAKE) client-stop N=1
	@$(MAKE) client N=1 REPO=$(REPO) BINARY=$(BINARY)

client2-up: check-env check-repo
	@$(MAKE) client N=2 REPO=$(REPO) BINARY=$(BINARY) BINARY_FILE=$(BINARY_FILE)

client2-down:
	@$(MAKE) client-stop N=2

# ============================================
# Troubleshoot
# ============================================

troubleshoot: check-env
	@bash troubleshoot.sh check $(if $(REPO),--repo $(REPO),)

troubleshoot-fix: check-env
	@bash troubleshoot.sh fix $(if $(REPO),--repo $(REPO),)

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
	@echo "Client Management (each client = one binary):"
	@echo "  make client N=1 REPO=test BINARY=alpha                  - Start client 1 (8803/8804)"
	@echo "  make client N=2 REPO=test BINARY=modules/beta BINARY_FILE=~/b - Start client 2 (8813/8814)"
	@echo "  make client N=3 REPO=aweme BINARY=38.1.0/all_init.o     - Start client 3 (8823/8824)"
	@echo "  make client-stop N=3   - Stop client 3"
	@echo "  make client-logs N=3   - View client 3 logs"
	@echo "  Ports: N=1→8803/8804, N=2→8813/8814, N=3→8823/8824, ..."
	@echo ""
	@echo "  Legacy aliases: client-up = client N=1, client2-up = client N=2"
	@echo ""
	@echo "Connect Ghidra GUI:"
	@echo "  1. File → New Project → Shared Project"
	@echo "  2. Server: localhost:$(GHIDRA_SERVER_PORT)"
	@echo "  3. User: root (password from server logs)"
	@echo "  4. Each client auto-registers as bridge-1, bridge-2, ..."
	@echo ""
