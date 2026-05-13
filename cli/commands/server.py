import click

from cli import config, docker, output

SVRADMIN = "/opt/ghidra/server/svrAdmin"
CONTAINER = "ghidra-server-standalone"
COMPOSE_FILE = "docker-compose.server.yml"


@click.group()
def server():
    """Manage the Ghidra Server."""


@server.command()
def up():
    """Start the standalone Ghidra Server."""
    cfg = config.load()
    cfg.ensure_data_dirs()
    output.header(f"Starting Ghidra Server (v{cfg.ghidra_version})...")
    docker.compose(cfg, ["up", "-d"], file=COMPOSE_FILE)
    output.success(f"Server started on port {cfg.server_port}")


@server.command()
def down():
    """Stop the Ghidra Server."""
    cfg = config.load()
    docker.compose(cfg, ["down"], file=COMPOSE_FILE)
    output.success("Server stopped")


@server.command()
def restart():
    """Restart the Ghidra Server."""
    cfg = config.load()
    output.header("Restarting Ghidra Server...")
    docker.compose(cfg, ["down"], file=COMPOSE_FILE)
    cfg.ensure_data_dirs()
    docker.compose(cfg, ["up", "-d"], file=COMPOSE_FILE)
    output.success(f"Server restarted on port {cfg.server_port}")


@server.command()
def logs():
    """Follow Ghidra Server logs."""
    cfg = config.load()
    docker.docker_logs(cfg, CONTAINER)


@server.command()
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def clean(yes):
    """Remove all server data (destructive)."""
    cfg = config.load()
    click.echo("This will remove:")
    click.echo(f"  - Docker volumes (repos + config)")
    click.echo(f"  - SSH keys ({cfg.version_dir / 'ssh/clients/'})")
    click.echo(f"  - Client configs ({cfg.version_dir / 'client-config-*/'})")
    if not yes:
        click.confirm("\nContinue?", abort=True)
    docker.compose(cfg, ["down", "-v"], file=COMPOSE_FILE)
    import shutil
    ssh_dir = cfg.version_dir / "ssh"
    if ssh_dir.exists():
        shutil.rmtree(ssh_dir)
    for d in cfg.version_dir.glob("client-config-*"):
        shutil.rmtree(d)
    output.success("Server data removed")


@server.command()
def users():
    """List all Ghidra Server users."""
    cfg = config.load()
    result = docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-users"])
    if result.returncode != 0:
        output.error("Server container not running. Run: gmcp server up")


@server.command("add-user")
@click.argument("name")
def add_user(name):
    """Add a user to the Ghidra Server (prompts for password)."""
    cfg = config.load()
    click.echo(f"Adding user: {name}")
    docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-add", name, "--p"], interactive=True)


@server.command("reset-password")
@click.argument("name")
def reset_password(name):
    """Reset a user's password (prompts for new password)."""
    cfg = config.load()
    click.echo(f"Resetting password for: {name}")
    docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-reset", name, "--p"], interactive=True)


@server.command()
def repos():
    """List all repositories on the Ghidra Server."""
    cfg = config.load()
    result = docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-list", "--users"])
    if result.returncode != 0:
        output.error("Server container not running. Run: gmcp server up")
