import json
import os
import platform
import re
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


def _write_agent_file(filename: str):
    """Write or update a project-level instruction file with skill content."""
    skill = _read_skill()
    target = _project_root() / filename
    block = f"{SKILL_MARKER}\n{skill}\n{SKILL_MARKER}"

    if target.is_file():
        existing = target.read_text()
        if SKILL_MARKER in existing:
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
    """Install skill to project-level AI instruction files."""


# ── Skill install targets ──────────────────────────────────

@install.command("codex")
def codex():
    """Install skill to AGENTS.md (OpenAI Codex)."""
    _write_agent_file("AGENTS.md")


@install.command("claude-code")
def claude_code():
    """Install skill to CLAUDE.md (Claude Code)."""
    _write_agent_file("CLAUDE.md")


@install.command("cursor")
def cursor():
    """Install skill to .cursor/rules/ghidra-mcp.md (Cursor)."""
    rules_dir = _project_root() / ".cursor" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    target = rules_dir / "ghidra-mcp.md"
    target.write_text(_read_skill())
    output.success(f"Created {target}")


@install.command("copilot")
def copilot():
    """Install skill to .github/copilot-instructions.md (GitHub Copilot)."""
    github_dir = _project_root() / ".github"
    github_dir.mkdir(parents=True, exist_ok=True)
    _write_agent_file(".github/copilot-instructions.md")


# ── MCP connection config ──────────────────────────────────

@install.command("mcp")
@click.argument("target", type=click.Choice(["claude-code", "claude-desktop", "coco"]))
@click.option("--port", "-p", default=8804, type=int, help="MCP SSE port (default: 8804).")
@click.option("--name", "-n", default="ghidra", help="MCP server name (default: ghidra).")
@click.option("--client", "-c", default=0, type=int, help="Client N (0=default port, 1-9=auto-calc).")
def mcp(target, port, name, client):
    """Configure MCP connection for an AI client."""
    if client > 0:
        _, sse_port = client_ports(client)
        port = sse_port
        if name == "ghidra":
            name = f"ghidra-{client}"

    if target == "claude-code":
        _mcp_claude_code(port, name)
    elif target == "claude-desktop":
        _mcp_claude_desktop(port, name)
    elif target == "coco":
        _mcp_coco(port, name)


def _mcp_claude_code(port: int, name: str):
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


def _mcp_claude_desktop(port: int, name: str):
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


def _mcp_coco(port: int, name: str):
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


# ── Skill info ─────────────────────────────────────────────

@install.command("skill")
def skill():
    """Show available install targets."""
    path = _skill_path()
    if path.is_file():
        output.success(f"Skill document: {path}")
        click.echo()
        click.echo("  Install skill:")
        click.echo("    gmcp install codex         # → AGENTS.md")
        click.echo("    gmcp install claude-code   # → CLAUDE.md")
        click.echo("    gmcp install cursor        # → .cursor/rules/ghidra-mcp.md")
        click.echo("    gmcp install copilot       # → .github/copilot-instructions.md")
        click.echo()
        click.echo("  Configure MCP connection:")
        click.echo("    gmcp install mcp claude-code")
        click.echo("    gmcp install mcp claude-desktop")
        click.echo("    gmcp install mcp coco")
    else:
        output.error(f"Skill document not found at {path}")
