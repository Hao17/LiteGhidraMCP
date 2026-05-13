from __future__ import annotations

import json
import subprocess

import click

from cli import config, output
from cli.ports import client_ports


def _probe_http(port: int, timeout: float = 2.0) -> dict | None:
    """Probe a Bridge HTTP API and return status, or None if unreachable."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", str(timeout), f"http://127.0.0.1:{port}/api/status"],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return None


def _probe_basic_info(port: int, timeout: float = 3.0) -> dict | None:
    """Get program info from a Bridge client."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", str(timeout), f"http://127.0.0.1:{port}/api/basic_info"],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return None


def _check_container(name: str) -> bool:
    """Check if a docker container is running."""
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and "true" in result.stdout.strip().lower()


def _collect_status(cfg: config.Config) -> dict:
    """Collect full status of server and all clients."""
    data: dict = {
        "config": {
            "ghidra_data_dir": cfg.ghidra_data_dir,
            "ghidra_version": cfg.ghidra_version,
            "server_port": cfg.server_port,
        },
        "server": {
            "container": "ghidra-server-standalone",
            "running": _check_container("ghidra-server-standalone"),
            "port": cfg.server_port,
        },
        "clients": [],
    }

    for n in range(1, 10):
        http_port, sse_port = client_ports(n)
        container = f"ghidra-mcp-bridge-client-{n}"
        running = _check_container(container)
        if not running:
            continue

        client_info: dict = {
            "id": n,
            "container": container,
            "running": True,
            "http_port": http_port,
            "sse_port": sse_port,
            "http_url": f"http://127.0.0.1:{http_port}",
            "mcp_url": f"http://127.0.0.1:{sse_port}/sse",
        }

        status = _probe_http(http_port)
        if status and status.get("success"):
            client_info["api_healthy"] = True

        basic = _probe_basic_info(http_port)
        if basic and basic.get("program"):
            prog = basic["program"]
            client_info["program"] = prog.get("name", "")
            client_info["format"] = prog.get("format", "")
            client_info["processor"] = prog.get("processor", "")
            funcs = prog.get("functions", {})
            client_info["functions"] = funcs.get("total_count", 0)

        data["clients"].append(client_info)

    return data


@click.command()
@click.option("--json-output", "--json", "as_json", is_flag=True, help="Output as JSON (machine-readable).")
def status(as_json):
    """Show running services, ports, and loaded binaries."""
    cfg = config.load()
    data = _collect_status(cfg)

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    # Human-readable output
    output.header("Ghidra MCP Bridge Status")
    click.echo(f"  Version: {data['config']['ghidra_version']}")
    click.echo()

    # Server
    srv = data["server"]
    if srv["running"]:
        output.success(f"Server: port {srv['port']}")
    else:
        output.info("Server: not running")

    # Clients
    clients = data["clients"]
    if not clients:
        click.echo()
        output.info("No clients running.")
        return

    click.echo()
    for c in clients:
        program = c.get("program", "unknown")
        processor = c.get("processor", "")
        funcs = c.get("functions", 0)
        healthy = c.get("api_healthy", False)

        tag = click.style("[OK]", fg="green") if healthy else click.style("[--]", fg="yellow")
        click.echo(f"  {tag} Client {c['id']}: {program}")
        click.echo(f"       {processor}  {funcs} functions")
        click.echo(f"       HTTP: {c['http_url']}  MCP: {c['mcp_url']}")
