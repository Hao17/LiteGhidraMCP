import os
import shutil

import click

from cli import config, docker, output
from cli.ports import client_ports

COMPOSE_FILE = "docker-compose.client.yml"


@click.group()
def client():
    """Manage Bridge clients (one per binary)."""


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
@click.option("--repo", "-r", required=True, help="Ghidra Server repository name.")
@click.option("--binary", "-b", default="", help="Program name or repo path to open.")
@click.option("--binary-file", "-f", type=click.Path(exists=True), help="Host binary file to import.")
def start(n, repo, binary, binary_file):
    """Start client N (1-9). Ports auto-calculated."""
    cfg = config.load()
    cfg.ensure_data_dirs()
    http_port, sse_port = client_ports(n)

    import_name = ""
    if binary_file:
        import_name = binary or os.path.basename(binary_file)
        imports_dir = cfg.imports_dir
        staged_path = imports_dir / import_name
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary_file, staged_path)
        output.info(f"Binary staged: {binary_file} → {staged_path}")

    env = {
        "CLIENT_ID": str(n),
        "CLIENT_MCP_PORT": str(http_port),
        "CLIENT_MCP_SSE_PORT": str(sse_port),
        "GHIDRA_SERVER_REPO": f"/{repo}",
        "PROGRAM_NAME": binary,
        "IMPORT_BINARY_NAME": import_name,
    }

    output.header(f"Starting client {n}...")
    docker.compose(
        cfg,
        ["up", "-d"],
        project=f"ghidra-client-{n}",
        file=COMPOSE_FILE,
        env_overrides=env,
    )
    output.success(f"Client {n} started")
    click.echo(f"  Repo:    {repo}")
    click.echo(f"  Binary:  {binary or '(first available)'}")
    click.echo(f"  HTTP:    http://localhost:{http_port}")
    click.echo(f"  MCP SSE: http://localhost:{sse_port}/sse")


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
def stop(n):
    """Stop client N."""
    cfg = config.load()
    docker.compose(
        cfg,
        ["down"],
        project=f"ghidra-client-{n}",
        file=COMPOSE_FILE,
    )
    output.success(f"Client {n} stopped")


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
def logs(n):
    """Follow client N logs."""
    cfg = config.load()
    docker.docker_logs(cfg, f"ghidra-mcp-bridge-client-{n}")
