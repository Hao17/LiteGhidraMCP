import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import click

from cli import config, output
from cli.ports import client_ports


def _sse_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/sse"


def _skill_path() -> Path:
    docker_dir = config.find_docker_dir()
    return docker_dir.parent / "docs" / "SKILL.md"


@click.group()
def install():
    """Configure AI clients to connect to Ghidra MCP Bridge."""


@install.command("claude-code")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--name", "-n", default="ghidra", help="MCP server name (default: ghidra).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def claude_code(port, name, client):
    """Add Ghidra MCP server to Claude Code."""
    if client > 0:
        _, sse_port = client_ports(client)
        port = sse_port
        if name == "ghidra":
            name = f"ghidra-{client}"

    if not shutil.which("claude"):
        output.error("'claude' command not found. Install Claude Code first.")
        raise SystemExit(1)

    url = _sse_url(port)
    result = subprocess.run(
        ["claude", "mcp", "add", "--transport", "sse", name, url],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        output.success(f"Added '{name}' → {url}")
    else:
        stderr = result.stderr.strip()
        if "already exists" in stderr.lower():
            output.warning(f"'{name}' already configured. Remove first: claude mcp remove {name}")
        else:
            output.error(f"Failed: {stderr or result.stdout.strip()}")

    _offer_skill()


@install.command("claude-desktop")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--name", "-n", default="ghidra", help="MCP server name (default: ghidra).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def claude_desktop(port, name, client):
    """Add Ghidra MCP server to Claude Desktop config."""
    if client > 0:
        _, sse_port = client_ports(client)
        port = sse_port
        if name == "ghidra":
            name = f"ghidra-{client}"

    system = platform.system()
    if system == "Darwin":
        config_path = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    elif system == "Linux":
        config_path = Path.home() / ".config/claude/settings.json"
    elif system == "Windows":
        config_path = Path(os.environ.get("APPDATA", "")) / "Claude/claude_desktop_config.json"
    else:
        output.error(f"Unsupported platform: {system}")
        raise SystemExit(1)

    config_data = {}
    if config_path.is_file():
        try:
            config_data = json.loads(config_path.read_text())
        except json.JSONDecodeError:
            output.warning(f"Could not parse {config_path}, creating new config")

    mcp_servers = config_data.setdefault("mcpServers", {})
    if name in mcp_servers:
        output.warning(f"'{name}' already exists in config. Overwriting.")

    mcp_servers[name] = {"type": "sse", "url": _sse_url(port)}

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config_data, indent=2) + "\n")
    output.success(f"Added '{name}' → {_sse_url(port)}")
    output.info(f"Config: {config_path}")
    output.info("Restart Claude Desktop to apply changes.")

    _offer_skill()


@install.command("coco")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--name", "-n", default="ghidra", help="MCP server name (default: ghidra).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def coco(port, name, client):
    """Add Ghidra MCP server to Coco."""
    if client > 0:
        _, sse_port = client_ports(client)
        port = sse_port
        if name == "ghidra":
            name = f"ghidra-{client}"

    if not shutil.which("coco"):
        output.error("'coco' command not found. Install Coco first.")
        raise SystemExit(1)

    url = _sse_url(port)
    mcp_json = json.dumps({"type": "sse", "url": url})
    result = subprocess.run(
        ["coco", "mcp", "add-json", name, mcp_json],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        output.success(f"Added '{name}' → {url}")
    else:
        output.error(f"Failed: {result.stderr.strip() or result.stdout.strip()}")

    _offer_skill()


@install.command("skill")
def skill():
    """Show the path to the usage skill document."""
    path = _skill_path()
    if path.is_file():
        output.success(f"Skill document: {path}")
        output.info("Add this file as context for your AI client to improve analysis quality.")
        click.echo()
        click.echo("For Claude Code, add to your project CLAUDE.md or use:")
        click.echo(f"  cat {path}")
    else:
        output.error(f"Skill document not found at {path}")


def _offer_skill():
    path = _skill_path()
    if path.is_file():
        click.echo()
        output.info(f"Usage tips: {path}")
        output.info("Run 'gmcp install skill' for details.")
