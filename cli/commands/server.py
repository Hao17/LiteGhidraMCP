import shutil
import subprocess
import time
from pathlib import Path

import click

from cli import config, docker, output

SVRADMIN = "/opt/ghidra/server/svrAdmin"
CONTAINER = "ghidra-server-standalone"
COMPOSE_FILE = "docker-compose.server.yml"
VALID_PERMS = ("+r", "+w", "+a")


def _ensure_bridgectl_key(cfg: config.Config) -> Path:
    """Ensure bridgectl SSH key exists on host; return private key path."""
    ctrl_dir = cfg.version_dir / "ssh" / "clients" / "bridgectl"
    ctrl_dir.mkdir(parents=True, exist_ok=True)
    priv = ctrl_dir / "ssh_key"
    if not priv.exists():
        output.info("Generating bridgectl SSH key for gmcp CLI automation...")
        r = subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-m", "PEM",
             "-f", str(priv), "-N", "", "-C", "bridgectl"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            output.error(f"ssh-keygen failed: {r.stderr}")
            raise click.Abort()
        priv.chmod(0o600)
        (ctrl_dir / "ssh_key.pub").chmod(0o644)
    return priv


def _acl_file(cfg: config.Config) -> Path:
    return cfg.version_dir / "repos" / ".bridge-acl.conf"


def _read_acl(cfg: config.Config) -> list[tuple[str, str, str]]:
    """Parse .bridge-acl.conf into [(user, repo, perm), ...]."""
    path = _acl_file(cfg)
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        user, repo, perm = parts[0], parts[1], parts[2]
        entries.append((user, repo, perm))
    return entries


def _write_acl(cfg: config.Config, entries: list[tuple[str, str, str]]) -> None:
    path = _acl_file(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# gmcp bridge ACL (managed by `gmcp server repo grant/revoke`)",
        "# format: <user> <repo|__all__> <+r|+w|+a>",
    ]
    for user, repo, perm in entries:
        lines.append(f"{user} {repo} {perm}")
    path.write_text("\n".join(lines) + "\n")


def _wait_for_repo_dir(cfg: config.Config, name: str, timeout: int = 15) -> bool:
    """Poll for the repo's filesystem dir (ACL sync grants take effect on next 5s tick)."""
    target = cfg.version_dir / "repos" / name.lstrip("/")
    for _ in range(timeout):
        if target.is_dir():
            return True
        time.sleep(1)
    return False


@click.group()
def server():
    """Manage the Ghidra Server."""


@server.command()
def up():
    """Start the standalone Ghidra Server."""
    cfg = config.load()
    cfg.ensure_data_dirs()
    _ensure_bridgectl_key(cfg)
    output.header(f"Starting Ghidra Server (v{cfg.ghidra_version})...")
    docker.compose(cfg, ["up", "-d"], file=COMPOSE_FILE)
    output.success(f"Server started on port {cfg.server_port}")

    admin_marker = cfg.version_dir / "config" / ".admin_user"
    if not admin_marker.exists():
        click.echo()
        click.echo("=" * 50)
        click.echo("  First-time Setup: Register Admin User")
        click.echo("=" * 50)
        click.echo("This account is for Ghidra GUI access.")
        click.echo("All repositories will auto-grant access to this user.")
        click.echo()
        name = click.prompt("Enter admin username (empty to skip)", default="", show_default=False)
        if not name:
            click.echo("Skipped. Run 'gmcp server add-user <name>' later.")
            return
        click.echo("Waiting for server to be ready...")
        for _ in range(30):
            r = docker.docker_exec(cfg, CONTAINER, ["nc", "-z", "localhost", "13100"],
                                   capture=True)
            if r.returncode == 0:
                break
            time.sleep(1)
        click.echo(f"Setting password for '{name}':")
        r = docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-add", name, "--p"], interactive=True)
        if r.returncode == 0:
            admin_marker.parent.mkdir(parents=True, exist_ok=True)
            admin_marker.write_text(name)
            output.success(f"Admin '{name}' registered. All repos will auto-grant access.")
        else:
            output.error(f"Registration failed. Run 'gmcp server add-user {name}' later.")


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
    admin_marker = cfg.version_dir / "config" / ".admin_user"
    admin_marker.unlink(missing_ok=True)
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


@server.command("migrate-acl")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def migrate_acl(yes):
    """One-shot migration: remove bridge-N legacy users + revoke their ACL from all repos.

    Cleans up the old slot-based identity model. After running, all repos rely on:
      - admin (password user) for GUI
      - bridgectl (SSH) for gmcp CLI automation
      - explicit grants in .bridge-acl.conf for clients
    """
    cfg = config.load()
    ssh_clients_dir = cfg.version_dir / "ssh" / "clients"
    if not ssh_clients_dir.is_dir():
        output.error(f"SSH clients dir not found: {ssh_clients_dir}")
        raise click.Abort()

    bridge_users = sorted(
        d.name for d in ssh_clients_dir.iterdir()
        if d.is_dir() and d.name.startswith("bridge-")
    )
    if not bridge_users:
        output.info("No bridge-* legacy users found. Nothing to migrate.")
        return

    repos_dir = cfg.version_dir / "repos"
    repo_names = sorted(
        d.name for d in repos_dir.iterdir()
        if d.is_dir() and not d.name.startswith(("~", "."))
    )

    click.echo("Migration plan:")
    click.echo(f"  Legacy bridge-* users: {', '.join(bridge_users)}")
    click.echo(f"  Repos to revoke from:  {', '.join(repo_names)}")
    click.echo("  Actions per user:")
    click.echo("    1. svrAdmin -revoke <user> <repo> (every repo)")
    click.echo("    2. svrAdmin -remove <user>")
    click.echo("    3. rm -rf ssh/clients/<user>/ + repos/~ssh/<user>.pub")
    if not yes:
        click.confirm("\nProceed?", abort=True)

    # Make sure server is running (svrAdmin needs the server process)
    ps = docker.docker_exec(cfg, CONTAINER, ["true"], capture=True)
    if ps.returncode != 0:
        output.error("Server container not running. Run: gmcp server up")
        raise click.Abort()

    pubkey_dir = repos_dir / "~ssh"
    for user in bridge_users:
        output.info(f"--- migrating {user} ---")
        for r in repo_names:
            docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-revoke", user, r], capture=True)
        rm = docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-remove", user], capture=True)
        if rm.returncode != 0:
            click.echo(f"  WARNING: svrAdmin -remove {user} failed (may not have been registered)")
        shutil.rmtree(ssh_clients_dir / user, ignore_errors=True)
        (pubkey_dir / f"{user}.pub").unlink(missing_ok=True)
        click.echo(f"  ✓ {user} removed")

    # Strip any legacy bridge-* entries from .bridge-acl.conf (defensive)
    entries = _read_acl(cfg)
    kept = [e for e in entries if not e[0].startswith("bridge-")]
    if len(kept) != len(entries):
        _write_acl(cfg, kept)
        output.info(f"Cleaned {len(entries) - len(kept)} legacy bridge-* entries from .bridge-acl.conf.")

    output.success(f"Migrated {len(bridge_users)} legacy user(s). Future clients use --user or ephemeral UUID.")


@server.group()
def repo():
    """Manage individual repositories (admin-owned model)."""


@repo.command("create")
@click.argument("name")
def repo_create(name):
    """Create a new repository owned by admin (uses bridgectl SSH key)."""
    cfg = config.load()
    name_bare = name.lstrip("/")
    _ensure_bridgectl_key(cfg)
    output.info(f"Creating repository '{name_bare}' as bridgectl...")
    r = docker.admin_bootstrap(cfg, ["create-repo", name_bare], capture=True)
    if r.returncode != 0:
        output.error(f"create-repo failed:\n{r.stderr or r.stdout}")
        raise click.Abort()
    msg = (r.stdout or "").strip()
    if msg.startswith("already-exists:"):
        output.info(f"Repository '{name_bare}' already exists.")
    else:
        output.success(f"Repository '{name_bare}' created. Admin + bridgectl have +a; grant clients with: gmcp server repo grant <user> {name_bare} +w")


@repo.command("delete")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def repo_delete(name, yes):
    """Delete a repository permanently (stops server, removes data, restarts)."""
    cfg = config.load()
    name_bare = name.lstrip("/")
    target = cfg.version_dir / "repos" / name_bare
    if not target.is_dir():
        output.error(f"Repository '{name_bare}' not found at {target}")
        raise click.Abort()
    size = subprocess.run(["du", "-sh", str(target)], capture_output=True, text=True).stdout.split()[0]
    click.echo(f"Will delete: {target} ({size})")
    click.echo("This removes ALL binaries and version history in this repository.")
    if not yes:
        click.confirm("Continue?", abort=True)
    output.info("Stopping server...")
    docker.compose(cfg, ["down"], file=COMPOSE_FILE)
    shutil.rmtree(target)
    output.success(f"Removed {target}")
    # Strip any grants for this repo from .bridge-acl.conf
    entries = _read_acl(cfg)
    kept = [e for e in entries if e[1] != name_bare]
    if len(kept) != len(entries):
        _write_acl(cfg, kept)
        output.info(f"Stripped {len(entries) - len(kept)} ACL entr(ies) for '{name_bare}'.")
    output.info("Restarting server...")
    docker.compose(cfg, ["up", "-d"], file=COMPOSE_FILE)
    output.success("Server restarted.")


@repo.command("grant")
@click.argument("user")
@click.argument("repo_name")
@click.argument("perm", type=click.Choice(VALID_PERMS))
def repo_grant(user, repo_name, perm):
    """Grant USER PERM (+r/+w/+a) on REPO. Use __all__ for cross-repo grant."""
    cfg = config.load()
    repo_bare = repo_name.lstrip("/")
    if repo_bare != "__all__":
        if not (cfg.version_dir / "repos" / repo_bare).is_dir():
            output.error(f"Repository '{repo_bare}' not found. Create it first: gmcp server repo create {repo_bare}")
            raise click.Abort()
    entries = _read_acl(cfg)
    # Replace any existing entry for (user, repo)
    entries = [e for e in entries if not (e[0] == user and e[1] == repo_bare)]
    entries.append((user, repo_bare, perm))
    _write_acl(cfg, entries)
    output.success(f"Granted {user} {perm} on {repo_bare}. Effective within ~5s (server ACL sync).")


@repo.command("revoke")
@click.argument("user")
@click.argument("repo_name")
def repo_revoke(user, repo_name):
    """Revoke USER's access on REPO (removes from .bridge-acl.conf + svrAdmin -revoke)."""
    cfg = config.load()
    repo_bare = repo_name.lstrip("/")
    entries = _read_acl(cfg)
    kept = [e for e in entries if not (e[0] == user and e[1] == repo_bare)]
    if len(kept) == len(entries):
        output.info(f"No grant found for {user} on {repo_bare} in .bridge-acl.conf (may still have legacy +a from prior config).")
    else:
        _write_acl(cfg, kept)
    # Best-effort hard revoke via svrAdmin (handles legacy grants too)
    if repo_bare == "__all__":
        for d in sorted((cfg.version_dir / "repos").iterdir()):
            if d.is_dir() and not d.name.startswith(("~", ".")):
                docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-revoke", user, d.name], capture=True)
    else:
        docker.docker_exec(cfg, CONTAINER, [SVRADMIN, "-revoke", user, repo_bare], capture=True)
    output.success(f"Revoked {user} on {repo_bare}.")


@repo.command("list")
def repo_list():
    """List repos with ACL entries from .bridge-acl.conf."""
    cfg = config.load()
    repos_dir = cfg.version_dir / "repos"
    if not repos_dir.is_dir():
        output.error("Repos dir not found. Run: gmcp server up")
        return
    repos = sorted(d.name for d in repos_dir.iterdir()
                   if d.is_dir() and not d.name.startswith(("~", ".")))
    entries = _read_acl(cfg)
    click.echo(f"Repositories ({len(repos)}):")
    for r in repos:
        click.echo(f"  {r}")
        grants = [(u, p) for u, rp, p in entries if rp == r or rp == "__all__"]
        for u, p in grants:
            click.echo(f"    grant: {u} {p}")
    if entries:
        cross = [(u, p) for u, rp, p in entries if rp == "__all__"]
        if cross:
            click.echo("\nCross-repo grants (__all__):")
            for u, p in cross:
                click.echo(f"  {u} {p}")
    click.echo("\nImplicit +a: admin password users, bridgectl (SSH)")
