import json
import subprocess

import click

from cli import config, docker, output


@click.group()
def dev():
    """Development mode commands."""


@dev.command()
def up():
    """Start in development mode (hot-reload enabled)."""
    cfg = config.load()
    output.header("Starting dev mode (hot-reload enabled)...")
    try:
        docker.compose(cfg, ["up"], file="docker-compose.dev.yml")
    except KeyboardInterrupt:
        pass


@dev.command()
@click.option("--port", "-p", default=8803, type=int, help="HTTP API port.")
def reload(port):
    """Hot-reload API modules."""
    output.header("Reloading API modules...")
    try:
        result = subprocess.run(
            ["curl", "-s", f"http://localhost:{port}/_reload"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            click.echo(json.dumps(data, indent=2))
        else:
            output.error(f"Failed to connect to localhost:{port}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        output.error(str(e))


@dev.command()
def health():
    """Check container health status."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "ghidra-mcp-bridge"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            health = data[0].get("State", {}).get("Health", {})
            click.echo(json.dumps(health, indent=2))
        else:
            output.error("Container not found: ghidra-mcp-bridge")
    except (json.JSONDecodeError, IndexError):
        output.error("Could not parse container info")


@dev.command()
@click.option("--port", "-p", default=8803, type=int, help="HTTP API port.")
def test(port):
    """Test API endpoints."""
    output.header("Testing API endpoints...")
    endpoints = [
        ("Status", f"http://localhost:{port}/api/status"),
        ("Basic Info", f"http://localhost:{port}/api/basic_info"),
        ("Search (main)", f"http://localhost:{port}/api/search/functions?q=main&limit=5"),
    ]
    for name, url in endpoints:
        click.echo(f"\n{name}:")
        try:
            result = subprocess.run(
                ["curl", "-s", url],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                click.echo(json.dumps(data, indent=2))
            else:
                output.error(f"No response from {url}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            output.error(f"Failed: {url}")


@dev.command()
def shell():
    """Open a shell in the Bridge container."""
    cfg = config.load()
    docker.docker_exec(cfg, "ghidra-mcp-bridge", ["/bin/bash"], interactive=True)


@dev.command("logs")
def dev_logs():
    """Follow docker-compose logs."""
    cfg = config.load()
    try:
        docker.compose(cfg, ["logs", "-f"])
    except KeyboardInterrupt:
        pass
