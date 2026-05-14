import os
import re
import shutil
import subprocess
import uuid as _uuid

import click

from cli import config, docker, output
from cli.commands.server import _read_acl, _write_acl
from cli.ports import client_ports

COMPOSE_FILE = "docker-compose.client.yml"

# Reserved/forbidden client identities
_RESERVED_USERS = {"bridgectl", "admin", "root", "anonymous"}
_VALID_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _ensure_client_key(cfg: config.Config, user: str) -> None:
    """Generate SSH keypair for user under ${SSH_DIR}/clients/<user>/ if missing."""
    udir = cfg.version_dir / "ssh" / "clients" / user
    udir.mkdir(parents=True, exist_ok=True)
    priv = udir / "ssh_key"
    if priv.exists():
        return
    output.info(f"Generating SSH key for user '{user}'...")
    r = subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "4096", "-m", "PEM",
         "-f", str(priv), "-N", "", "-C", user],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        output.error(f"ssh-keygen failed: {r.stderr}")
        raise click.Abort()
    priv.chmod(0o600)
    (udir / "ssh_key.pub").chmod(0o644)


def _grant_in_acl(cfg: config.Config, user: str, repo_bare: str, perm: str = "+w") -> None:
    entries = _read_acl(cfg)
    # Replace any existing entry for (user, repo)
    entries = [e for e in entries if not (e[0] == user and e[1] == repo_bare)]
    entries.append((user, repo_bare, perm))
    _write_acl(cfg, entries)


@click.group()
def client():
    """Manage Bridge clients (one per binary)."""


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
@click.option("--repo", "-r", required=True, help="Ghidra Server repository name.")
@click.option("--binary", "-b", default="", help="Program name or repo path to open.")
@click.option("--binary-file", "-f", type=click.Path(exists=True), help="Host binary file to import.")
@click.option("--user", "-u", "user_arg", default="", help="Explicit client identity (SSH user). Default: ephemeral UUID.")
def start(n, repo, binary, binary_file, user_arg):
    """Start client N (1-9). Ports auto-calculated. Identity defaults to fresh UUID."""
    cfg = config.load()
    cfg.ensure_data_dirs()
    http_port, sse_port = client_ports(n)

    # Validate repo exists (admin-owned model: clients can't create repos)
    repo_bare = repo.lstrip("/")
    if not (cfg.version_dir / "repos" / repo_bare).is_dir():
        output.error(f"Repository '{repo_bare}' does not exist. Create it first:")
        click.echo(f"  gmcp server repo create {repo_bare}")
        raise click.Abort()

    # Resolve client identity
    if user_arg:
        user = user_arg
        if user in _RESERVED_USERS:
            output.error(f"User '{user}' is reserved.")
            raise click.Abort()
        if not _VALID_USER_RE.match(user):
            output.error(f"Invalid user name '{user}' (allowed: [A-Za-z0-9._-], 1-64 chars).")
            raise click.Abort()
    else:
        user = f"u-{_uuid.uuid4().hex[:12]}"
        output.info(f"Ephemeral identity: {user}")

    # Generate SSH key (idempotent) + write +w grant (idempotent replace)
    _ensure_client_key(cfg, user)
    _grant_in_acl(cfg, user, repo_bare, "+w")
    output.info(f"Granted {user} +w on {repo_bare} (effective within ~5s via ACL sync).")

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
        "GHIDRA_SERVER_REPO": f"/{repo_bare}",
        "PROGRAM_NAME": binary,
        "IMPORT_BINARY_NAME": import_name,
        "AUTO_SERVER_USER": user,
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
    click.echo(f"  User:    {user}")
    click.echo(f"  Repo:    {repo_bare}")
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
