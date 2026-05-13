import click

from cli.commands.build import build, rebuild
from cli.commands.client import client
from cli.commands.dev import dev
from cli.commands.info import info, switch_version, versions
from cli.commands.install import install
from cli.commands.server import server
from cli.commands.stack import down, up
from cli.commands.status import status
from cli.commands.troubleshoot import troubleshoot


@click.group()
@click.version_option(package_name="ghidra-mcp-bridge")
def cli():
    """gmcp - Ghidra MCP Bridge Docker manager."""


cli.add_command(server)
cli.add_command(client)
cli.add_command(up)
cli.add_command(down)
cli.add_command(build)
cli.add_command(rebuild)
cli.add_command(dev)
cli.add_command(info)
cli.add_command(versions)
cli.add_command(switch_version)
cli.add_command(status)
cli.add_command(install)
cli.add_command(troubleshoot)
