# Ghidra MCP Bridge
# Makefile for common Docker operations

.PHONY: help build up down logs shell test clean rebuild

# Default target
help:
	@echo "Ghidra MCP Bridge (PyGhidra)"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build Docker image"
	@echo "  up         - Start services (detached)"
	@echo "  up-dev     - Start in development mode (with logs)"
	@echo "  down       - Stop services"
	@echo "  logs       - View logs (follow)"
	@echo "  shell      - Access container shell"
	@echo "  test       - Test API endpoints"
	@echo "  reload     - Hot reload API modules"
	@echo "  clean      - Remove containers and images"
	@echo "  rebuild    - Clean + Build + Up"
	@echo "  health     - Check container health"
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
