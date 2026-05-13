import click

from cli import config, docker


@click.group()
def troubleshoot():
    """Diagnose and fix Ghidra MCP Bridge issues."""


@troubleshoot.command()
@click.option("--repo", default="", help="Filter to specific repository.")
def check(repo):
    """Detect problems and show diagnostic summary."""
    cfg = config.load()
    args = ["bash", "troubleshoot.sh", "check"]
    if repo:
        args += ["--repo", repo]
    docker.run_script(cfg, args)


@troubleshoot.command()
@click.option("--repo", default="", help="Filter to specific repository.")
def fix(repo):
    """Auto-fix detected problems."""
    cfg = config.load()
    args = ["bash", "troubleshoot.sh", "fix"]
    if repo:
        args += ["--repo", repo]
    docker.run_script(cfg, args)
