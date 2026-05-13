import re
from pathlib import Path

import click

from cli import config, output


@click.command()
def info():
    """Show current configuration."""
    cfg = config.load()
    output.header("Ghidra MCP Bridge Configuration")
    click.echo(f"  Data Root:    {cfg.ghidra_data_dir}")
    click.echo(f"  Version:      {cfg.ghidra_version}")
    click.echo(f"  Server Port:  {cfg.server_port}")
    click.echo()
    click.echo("  Data Location:")
    click.echo(f"    Server Repos:   {cfg.version_dir / 'repos'}")
    click.echo(f"    Server Config:  {cfg.version_dir / 'config'}")
    click.echo(f"    SSH Keys:       {cfg.version_dir / 'ssh/clients/'}")
    click.echo(f"    Logs:           {Path(cfg.ghidra_data_dir) / 'logs' / cfg.ghidra_version}")
    click.echo()
    _list_versions(cfg)


@click.command()
def versions():
    """List available Ghidra versions."""
    cfg = config.load()
    _list_versions(cfg)


@click.command("switch-version")
@click.argument("version")
def switch_version(version):
    """Switch to a different Ghidra version."""
    cfg = config.load()
    env_file = cfg.docker_dir / ".env"
    if not env_file.is_file():
        output.error("No .env file found in docker/")
        return
    text = env_file.read_text()
    new_text = re.sub(r"^GHIDRA_VERSION=.*$", f"GHIDRA_VERSION={version}", text, flags=re.MULTILINE)
    if new_text == text:
        output.warning("GHIDRA_VERSION line not found in .env — appending")
        new_text += f"\nGHIDRA_VERSION={version}\n"
    env_file.write_text(new_text)
    output.success(f"Switched to version {version}")


def _list_versions(cfg: config.Config):
    data_dir = Path(cfg.ghidra_data_dir)
    if not data_dir.is_dir():
        click.echo("  (no data directory)")
        return
    dirs = sorted(d.name for d in data_dir.iterdir() if d.is_dir() and d.name != "logs")
    if dirs:
        current = cfg.ghidra_version
        click.echo("  Available versions:")
        for d in dirs:
            marker = " (active)" if d == current else ""
            click.echo(f"    {d}{marker}")
    else:
        click.echo("  (no versions found)")
