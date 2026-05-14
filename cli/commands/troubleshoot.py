import click

from cli import config, docker, output
from cli.commands.client import (
    _list_repo_checkout_holders,
    _live_ephemeral_users,
    _release_stranded_ephemeral_locks,
    _is_ephemeral_user,
)


@click.group()
def troubleshoot():
    """Diagnose and fix Ghidra MCP Bridge issues."""


def _classify_holder(user: str, live_users: set) -> str:
    """Bucket a checkout holder into one of:
    - 'live'     — ephemeral identity with a running container (expected)
    - 'stranded' — ephemeral identity with no live container (orphan lock)
    - 'named'    — non-ephemeral user (admin GUI, named SSH user, bridgectl)
    """
    if _is_ephemeral_user(user):
        return "live" if user in live_users else "stranded"
    return "named"


def _print_server_side_checkouts(cfg, repo_filter):
    """Query the server (via bridgectl) for every checkout on every repo and
    print holder details classified as live/stranded/named.

    This complements the on-disk `checkout.dat` scan in `troubleshoot.sh`:
    Ghidra Server may track checkouts that haven't been flushed to disk yet,
    so a disk-only scan can miss the actual holder of a lock that's
    blocking new clients. Listing via the RepositoryAdapter API is
    authoritative.
    """
    repos_dir = cfg.version_dir / "repos"
    if not repos_dir.is_dir():
        return 0

    if repo_filter:
        repos = [repo_filter.lstrip("/")]
    else:
        repos = sorted(d.name for d in repos_dir.iterdir()
                       if d.is_dir() and not d.name.startswith(("~", ".")))

    click.echo(click.style("Server-Side Checkouts (live query)", bold=True))
    live = _live_ephemeral_users(cfg)
    total_problems = 0
    any_shown = False

    for r in repos:
        holders = _list_repo_checkout_holders(cfg, r)
        if holders is None:
            click.echo(f"  [WARN] {r}: could not query (server unreachable?)")
            continue
        if not holders:
            continue
        for user, folder, fname, cid in holders:
            kind = _classify_holder(user, live)
            path = f"{r}:{folder.rstrip('/')}/{fname}"
            if kind == "live":
                output.info(f"  [OK] {path} held by {user} (live MCP)")
            elif kind == "stranded":
                click.echo(f"  [PROBLEM] {path} held by {user} (STRANDED — no live container)")
                total_problems += 1
            else:
                output.info(f"  [INFO] {path} held by {user} (named identity — admin GUI or SSH user)")
            any_shown = True

    if not any_shown:
        output.info("  No server-side checkouts found.")
    click.echo()
    return total_problems


@troubleshoot.command()
@click.option("--repo", default="", help="Filter to specific repository.")
def check(repo):
    """Detect problems and show diagnostic summary, including all live checkout holders."""
    cfg = config.load()
    args = ["bash", "troubleshoot.sh", "check"]
    if repo:
        args += ["--repo", repo]
    docker.run_script(cfg, args)
    stranded = _print_server_side_checkouts(cfg, repo)
    if stranded:
        click.echo(click.style(f"  {stranded} stranded checkout(s) found.", fg="red"))
        click.echo(f"  Run {click.style('gmcp troubleshoot fix' + (f' --repo {repo}' if repo else ''), bold=True)} to release them.")
        click.echo()


@troubleshoot.command()
@click.option("--repo", default="", help="Filter to specific repository.")
def fix(repo):
    """Auto-fix detected problems (releases stranded ephemeral checkouts)."""
    cfg = config.load()
    args = ["bash", "troubleshoot.sh", "fix"]
    if repo:
        args += ["--repo", repo]
    docker.run_script(cfg, args)

    # Server-side cleanup via bridgectl — catches strays the disk scan misses.
    repos_dir = cfg.version_dir / "repos"
    if not repos_dir.is_dir():
        return
    if repo:
        targets = [repo.lstrip("/")]
    else:
        targets = sorted(d.name for d in repos_dir.iterdir()
                         if d.is_dir() and not d.name.startswith(("~", ".")))

    click.echo(click.style("Releasing stranded ephemeral checkouts via bridgectl...", bold=True))
    total = 0
    for r in targets:
        total += _release_stranded_ephemeral_locks(cfg, r)
    if total == 0:
        output.success("No stranded ephemeral checkouts to release.")
    else:
        output.success(f"Released {total} stranded checkout(s).")
