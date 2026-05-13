import click

from cli import config, docker, output


@click.command()
def build():
    """Build the Docker image."""
    cfg = config.load()
    output.header("Building Docker image...")
    docker.compose(cfg, ["build"])


@click.command()
def rebuild():
    """Clean + build + start services."""
    cfg = config.load()
    output.header("Rebuilding everything...")
    docker.compose(cfg, ["down", "-v"])
    docker.compose(cfg, ["build"])
    docker.compose(cfg, ["up", "-d"])
    output.success("Rebuild complete")
