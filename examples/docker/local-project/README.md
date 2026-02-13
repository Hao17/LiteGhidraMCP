# Local Project Mode - Docker Deployment

This example demonstrates deploying Ghidra MCP Bridge in Docker using a **local Ghidra shared project** mounted as a volume.

## Prerequisites

1. **Ghidra shared project** created on your host machine
2. Docker and Docker Compose installed
3. MCP Bridge Docker image built (or will be built automatically)

## Directory Structure

Your Ghidra project should have this structure:

```
/path/to/your/ghidra-project/
├── my_binary.gpr          # Project configuration file
└── my_binary.rep/         # Project repository directory
    ├── idata/
    ├── user/
    └── versioned/
```

## Configuration Steps

### 1. Edit `.env` file

Update the following variables:

```bash
# Update to your actual project path on the host
HOST_PROJECT_PATH=/Users/username/ghidra-projects/my_binary

# Update to match your project name
PROJECT_NAME=my_binary
```

**Important**: `PROJECT_NAME` must match the `.gpr` and `.rep` filenames in your project directory.

### 2. Launch the container

```bash
docker-compose up -d
```

### 3. Verify the service

Check logs:
```bash
docker-compose logs -f
```

Test API:
```bash
curl http://localhost:8803/api/status
curl http://localhost:8803/api/basic_info
```

### 4. Configure MCP client

#### Coco Configuration

Add to your Coco configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

#### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://localhost:8804/sse"
    }
  }
}
```

## Troubleshooting

### Container won't start

Check if project path is correct:
```bash
ls -la /path/to/your/ghidra-project/
```

View detailed logs:
```bash
docker-compose logs ghidra-bridge
```

### API not responding

Check container health:
```bash
docker ps
```

Look for `(healthy)` status. If unhealthy, check logs.

### Project not found

Ensure `PROJECT_NAME` in `.env` matches the `.gpr` filename without extension:
- File: `my_binary.gpr` → `PROJECT_NAME=my_binary`

## Stopping the Service

```bash
docker-compose down
```

To remove volumes (logs):
```bash
docker-compose down -v
```

## Advanced: Multi-Client Collaboration

This setup allows multiple clients to access the same Ghidra project:

```
┌────────────────┐
│  Ghidra GUI    │
│  (User)        │
└───────┬────────┘
        │
        v
┌────────────────────────────────────┐
│  Ghidra Shared Project (Volume)    │
│  /path/to/project/                 │
└───────┬────────────────────────────┘
        │
        v
┌────────────────┐
│  Docker Bridge │
│  (MCP Server)  │
└────────────────┘
```

Both Ghidra GUI and Docker container access the same project files. Changes made by one are visible to the other (with appropriate locking/refresh).
