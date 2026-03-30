#!/bin/bash
# Health check for the headless bridge runtime.
# Verifies:
# 1. The PyGhidra HTTP API is responding and returning a healthy JSON payload.
# 2. The MCP SSE proxy is listening and can complete an HTTP handshake on /sse.

set -eu

HOST="${HEALTHCHECK_HOST:-127.0.0.1}"
TIMEOUT="${HEALTHCHECK_TIMEOUT:-3}"

status_url="${HEALTHCHECK_STATUS_URL:-http://${HOST}:${GHIDRA_MCP_PORT:-8803}/api/status}"
mcp_host="${HEALTHCHECK_MCP_HOST:-$HOST}"
mcp_port="${HEALTHCHECK_MCP_PORT:-${GHIDRA_MCP_SSE_PORT:-8804}}"
mcp_path="${HEALTHCHECK_MCP_PATH:-/sse}"

fail() {
    echo "Health check failed: $1" >&2
    exit 1
}

check_server_mode() {
    local server_port
    server_port="${GHIDRA_SERVER_PORT:-13100}"

    if nc -z "${HOST}" "${server_port}" > /dev/null 2>&1; then
        echo "Health check passed: Ghidra Server listening on ${HOST}:${server_port}"
        exit 0
    fi

    fail "Ghidra Server not listening on ${HOST}:${server_port}"
}

check_http_api() {
    local status_json

    status_json="$(curl -fsS --max-time "${TIMEOUT}" "${status_url}")" || \
        fail "HTTP API not responding at ${status_url}"

    STATUS_JSON="${status_json}" python3 - <<'PY' || exit 1
import json
import os
import sys

try:
    data = json.loads(os.environ["STATUS_JSON"])
except Exception as exc:
    print(f"invalid JSON payload: {exc}", file=sys.stderr)
    raise SystemExit(1)

if not data.get("success"):
    print(f"status endpoint returned unhealthy payload: {data}", file=sys.stderr)
    raise SystemExit(1)
PY
}

check_mcp_sse() {
    HEALTHCHECK_MCP_HOST="${mcp_host}" \
    HEALTHCHECK_MCP_PORT="${mcp_port}" \
    HEALTHCHECK_MCP_PATH="${mcp_path}" \
    HEALTHCHECK_TIMEOUT="${TIMEOUT}" \
    python3 - <<'PY' || exit 1
import os
import socket
import sys

host = os.environ["HEALTHCHECK_MCP_HOST"]
port = int(os.environ["HEALTHCHECK_MCP_PORT"])
path = os.environ["HEALTHCHECK_MCP_PATH"]
timeout = float(os.environ["HEALTHCHECK_TIMEOUT"])

request = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Accept: text/event-stream\r\n"
    "Connection: close\r\n\r\n"
).encode("ascii")

try:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = sock.recv(4096)
except Exception as exc:
    print(f"mcp socket check failed: {exc}", file=sys.stderr)
    raise SystemExit(1)

if not response:
    print("mcp socket check failed: empty response", file=sys.stderr)
    raise SystemExit(1)

header = response.decode("latin-1", "ignore")
status_line = header.split("\r\n", 1)[0]
header_lower = header.lower()

if " 200 " not in status_line and " 204 " not in status_line:
    print(f"unexpected MCP response: {status_line}", file=sys.stderr)
    raise SystemExit(1)

if "text/event-stream" not in header_lower:
    print(f"unexpected MCP content-type in response: {status_line}", file=sys.stderr)
    raise SystemExit(1)
PY
}

if [ "${RUN_MODE:-CLIENT}" = "SERVER" ]; then
    check_server_mode
fi

check_http_api || fail "HTTP API unhealthy"
check_mcp_sse || fail "MCP SSE unhealthy"

echo "Health check passed: HTTP API and MCP SSE are ready"
