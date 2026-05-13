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


def _project_root() -> Path:
    return config.find_docker_dir().parent


def _skill_path() -> Path:
    return _project_root() / "docs" / "SKILL.md"


def _read_skill() -> str:
    path = _skill_path()
    if not path.is_file():
        output.error(f"Skill document not found at {path}")
        raise SystemExit(1)
    return path.read_text()


SKILL_MARKER = "<!-- ghidra-mcp-skill -->"


def _write_agent_file(filename: str, label: str, mcp_port: int = 8804):
    """Write or update a project-level instruction file with skill content."""
    skill = _read_skill()
    mcp_block = _mcp_instructions_block(mcp_port)
    target = _project_root() / filename
    block = f"{SKILL_MARKER}\n{skill}\n{mcp_block}\n{SKILL_MARKER}"

    if target.is_file():
        existing = target.read_text()
        if SKILL_MARKER in existing:
            import re
            new_text = re.sub(
                rf"{re.escape(SKILL_MARKER)}.*?{re.escape(SKILL_MARKER)}",
                block,
                existing,
                flags=re.DOTALL,
            )
            target.write_text(new_text)
            output.success(f"Updated Ghidra MCP skill in {filename}")
        else:
            target.write_text(existing.rstrip() + "\n\n" + block + "\n")
            output.success(f"Appended Ghidra MCP skill to {filename}")
    else:
        target.write_text(block + "\n")
        output.success(f"Created {filename} with Ghidra MCP skill")

    output.info(f"Path: {target}")


@click.group()
def install():
    """Install skill or configure AI clients for Ghidra MCP Bridge."""


@install.command("claude-code")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--name", "-n", default="ghidra", help="MCP server name (default: ghidra).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
@click.option("--skip-skill", is_flag=True, help="Skip writing skill to CLAUDE.md.")
def claude_code(port, name, client, skip_skill):
    """Add MCP server to Claude Code + install skill to CLAUDE.md."""
    if client > 0:
        _, sse_port = client_ports(client)
        port = sse_port
        if name == "ghidra":
            name = f"ghidra-{client}"

    # MCP connection
    if not shutil.which("claude"):
        output.error("'claude' command not found. Install Claude Code first.")
        raise SystemExit(1)

    url = _sse_url(port)
    result = subprocess.run(
        ["claude", "mcp", "add", "--transport", "sse", name, url],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        output.success(f"MCP: added '{name}' → {url}")
    else:
        stderr = result.stderr.strip()
        if "already exists" in stderr.lower():
            output.warning(f"MCP: '{name}' already configured. Remove first: claude mcp remove {name}")
        else:
            output.error(f"MCP: {stderr or result.stdout.strip()}")

    # Skill
    if not skip_skill:
        _write_agent_file("CLAUDE.md", "Claude Code")


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


@install.command("codex")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def codex(port, client):
    """Install skill + MCP config to AGENTS.md (OpenAI Codex)."""
    if client > 0:
        _, port = client_ports(client)

    _write_agent_file("AGENTS.md", "Codex", mcp_port=port)


@install.command("cursor")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def cursor(port, client):
    """Install skill to .cursor/rules/ghidra-mcp.md (Cursor)."""
    if client > 0:
        _, port = client_ports(client)

    rules_dir = _project_root() / ".cursor" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    skill = _read_skill()
    mcp_block = _mcp_instructions_block(port)
    target = rules_dir / "ghidra-mcp.md"
    target.write_text(skill + "\n" + mcp_block)
    output.success(f"Installed Ghidra MCP skill to {target}")


@install.command("copilot")
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def copilot(port, client):
    """Install skill to .github/copilot-instructions.md (GitHub Copilot)."""
    if client > 0:
        _, port = client_ports(client)

    github_dir = _project_root() / ".github"
    github_dir.mkdir(parents=True, exist_ok=True)
    _write_agent_file(".github/copilot-instructions.md", "Copilot", mcp_port=port)


@install.command("skill")
def skill():
    """Show available install targets for the skill document."""
    path = _skill_path()
    if path.is_file():
        output.success(f"Skill document: {path}")
        click.echo()
        click.echo("  Install targets:")
        click.echo("    gmcp install claude-code   # CLAUDE.md + MCP connection")
        click.echo("    gmcp install codex         # AGENTS.md + MCP instructions")
        click.echo("    gmcp install cursor        # .cursor/rules/ghidra-mcp.md")
        click.echo("    gmcp install copilot       # .github/copilot-instructions.md")
        click.echo("    gmcp install claude-desktop # Claude Desktop config.json")
        click.echo("    gmcp install coco          # Coco MCP config")
    else:
        output.error(f"Skill document not found at {path}")


def _mcp_instructions_block(port: int) -> str:
    """Generate MCP connection instructions to embed in agent files."""
    return (
        "\n---\n\n"
        "## MCP Connection\n\n"
        f"Ghidra MCP SSE endpoint: `{_sse_url(port)}`\n\n"
        "Use `gmcp status --json` to discover all running clients, ports, and loaded binaries.\n"
    )
