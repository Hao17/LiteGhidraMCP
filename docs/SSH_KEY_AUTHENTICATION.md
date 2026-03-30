# SSH Key Authentication for Ghidra Server

This document describes the SSH key flow used by the current PyGhidra headless bridge.

## Overview

- Password authentication is no longer used by the Bridge runtime.
- Authenticated server mode requires `GHIDRA_SERVER_USER` plus `GHIDRA_SERVER_KEYSTORE`.
- In the bundled separated server-client deployment, Bridge client keys are generated and registered automatically.

There are two practical scenarios:

1. Bundled server-client mode in this repository.
2. Connecting the Bridge to an existing external Ghidra Server.

---

## Scenario 1: Bundled Server-Client Mode

This is the default workflow for this repository.

### How it works

- Start the standalone server with `docker/docker-compose.server.yml`.
- Start one or more Bridge clients with `docker/docker-compose.client.yml`.
- Each client auto-generates an SSH key under:
  `${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh/clients/bridge-<N>/ssh_key`
- The server scans `/ssh/clients/*/ssh_key.pub`, installs keys into `/repos/~ssh/<user>.pub`, and auto-registers the user.

### First-time setup

```bash
cd docker
cp .env.example .env
vim .env
```

Set at least:

```bash
GHIDRA_DATA_DIR=~/ghidra-data
GHIDRA_VERSION=12.0.3
```

### Start the server and a client

```bash
cd docker
make server-up
make client N=1 REPO=test
```

### Inspect generated keys

```bash
ls -la ~/ghidra-data/12.0.3/ssh/clients/bridge-1/
```

Expected files:

- `ssh_key`
- `ssh_key.pub`

### Verify registration

```bash
cd docker
make server-users
```

You should see the generated client user such as `bridge-1`.

### GUI connection note

The bundled standalone server exposes a `root` account for GUI login. To connect Ghidra GUI:

```bash
cd docker
make server-logs
```

Use the printed `root` password in Ghidra GUI when opening a Shared Project. This is separate from the Bridge client's SSH key flow.

---

## Scenario 2: External Ghidra Server

Use this when you already have a Ghidra Server running outside this repository.

### Step 1: Generate a key pair

Use PEM RSA format so Ghidra can read it reliably:

```bash
mkdir -p ~/.ghidra
ssh-keygen -t rsa -b 4096 -m PEM -f ~/.ghidra/bridge_key -N ""
chmod 600 ~/.ghidra/bridge_key
chmod 644 ~/.ghidra/bridge_key.pub
```

### Step 2: Register the public key on the server

Create the user and install the public key on the Ghidra Server host:

```bash
cd /path/to/ghidra/server
./svrAdmin -add bridge
```

Then place the public key into the server SSH key store:

```bash
mkdir -p /path/to/repos/~ssh
cp ~/.ghidra/bridge_key.pub /path/to/repos/~ssh/bridge.pub
```

The repository root may differ on your deployment. In this repository's bundled server image it is mounted at `/repos`.

### Step 3: Configure the Bridge runtime

The Bridge process needs these environment variables:

```bash
PROJECT_MODE=server
GHIDRA_SERVER_HOST=<server-host>
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=bridge
GHIDRA_SERVER_REPO=/mcp-projects
GHIDRA_SERVER_KEYSTORE=/root/.ghidra/ssh_key
```

If you run the Bridge in Docker, mount the private key read-only:

```bash
- ~/.ghidra/bridge_key:/root/.ghidra/ssh_key:ro
```

### Step 4: Verify the connection

You should see logs similar to:

```text
[PyGhidra-MCP-Bridge] Connecting to Ghidra Server: <host>:13100
[PyGhidra-MCP-Bridge] User: bridge
[PyGhidra-MCP-Bridge] Authentication: SSH key (/root/.ghidra/ssh_key)
[PyGhidra-MCP-Bridge] ✓ SSH key authenticator installed
[PyGhidra-MCP-Bridge] ✓ Connected to server
```

---

## Troubleshooting

### SSH keystore not found

The configured private key path is wrong or not mounted into the container.

```bash
ls -la ~/.ghidra/bridge_key
```

### Authentication failed

Check that:

- The server user exists.
- The public key was installed on the server.
- The private and public keys match.

Useful commands:

```bash
ssh-keygen -lf ~/.ghidra/bridge_key
ssh-keygen -lf ~/.ghidra/bridge_key.pub
```

### Unsupported private key format

Regenerate the key in PEM format:

```bash
ssh-keygen -t rsa -b 4096 -m PEM -f ~/.ghidra/bridge_key -N ""
```

### Connection refused

Verify the Ghidra Server is listening:

```bash
nc -zv <server-host> 13100
```

---

## Security Notes

- Use one key per user or automation identity.
- Rotate keys periodically.
- Do not commit private keys.
- For shared environments, prefer separate keys for dev and prod.

---

## Quick Reference

```bash
# Bundled mode
cd docker
cp .env.example .env
make server-up
make client N=1 REPO=test

# External server key generation
mkdir -p ~/.ghidra
ssh-keygen -t rsa -b 4096 -m PEM -f ~/.ghidra/bridge_key -N ""
chmod 600 ~/.ghidra/bridge_key
chmod 644 ~/.ghidra/bridge_key.pub
```

See also:

- `README.md`
- `docker/QUICKSTART.md`
- `docs/SSH_KEY_TESTING.md`
