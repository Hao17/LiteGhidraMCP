import os
import shutil

import click

from cli import config, docker, output
from cli.commands.server import COMPOSE_FILE as SERVER_COMPOSE
from cli.ports import client_ports

CLIENT_COMPOSE = "docker-compose.client.yml"


@click.command()
@click.option("--repo", "-r", required=True, help="Ghidra Server repository name.")
@click.option("--binary", "-b", default="", help="Program name or repo path to open.")
@click.option("--binary-file", "-f", type=click.Path(exists=True), help="Host binary file to import.")
def up(repo, binary, binary_file):
    """Start server + client 1 in one command."""
    cfg = config.load()
    cfg.ensure_data_dirs()

    # Server
    output.header(f"Starting Ghidra Server (v{cfg.ghidra_version})...")
    docker.compose(cfg, ["up", "-d"], file=SERVER_COMPOSE)
    output.success(f"Server started on port {cfg.server_port}")
    click.echo()

    # Client 1
    http_port, sse_port = client_ports(1)
    import_name = ""
    if binary_file:
        import_name = binary or os.path.basename(binary_file)
        cfg.imports_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary_file, cfg.imports_dir / import_name)
        output.info(f"Binary staged: {binary_file}")

    env = {
        "CLIENT_ID": "1",
        "CLIENT_MCP_PORT": str(http_port),
        "CLIENT_MCP_SSE_PORT": str(sse_port),
        "GHIDRA_SERVER_REPO": f"/{repo}",
        "PROGRAM_NAME": binary,
        "IMPORT_BINARY_NAME": import_name,
    }
    output.header("Starting client 1...")
    docker.compose(cfg, ["up", "-d"], project="ghidra-client-1", file=CLIENT_COMPOSE, env_overrides=env)
    output.success("Client 1 started")
    click.echo(f"  Repo:    {repo}")
    click.echo(f"  Binary:  {binary or '(first available)'}")
    click.echo(f"  HTTP:    http://localhost:{http_port}")
    click.echo(f"  MCP SSE: http://localhost:{sse_port}/sse")


@click.command()
def down():
    """Stop all services (server + all clients)."""
    cfg = config.load()
    output.header("Stopping all services...")
    for i in range(1, 10):
        docker.compose(cfg, ["down"], project=f"ghidra-client-{i}", file=CLIENT_COMPOSE, quiet=True)
    docker.compose(cfg, ["down"], file=SERVER_COMPOSE)
    output.success("All services stopped")
