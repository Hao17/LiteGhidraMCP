import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid as _uuid

import click

from cli import config, docker, output
from cli.commands.server import (
    CONTAINER as SERVER_CONTAINER,
    SVRADMIN,
    _read_acl,
    _write_acl,
)
from cli.ports import client_ports

COMPOSE_FILE = "docker-compose.client.yml"

# Reserved/forbidden client identities
_RESERVED_USERS = {"bridgectl", "admin", "root", "anonymous"}
_VALID_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Ephemeral users created by `gmcp client start` (no explicit --user) match this
# prefix and are eligible for full teardown on stop / clean.
_EPHEMERAL_PREFIX = "u-"


def _is_ephemeral_user(user: str) -> bool:
    return user.startswith(_EPHEMERAL_PREFIX)


# ---------------------------------------------------------------------------
# Session metadata: ${SSH_DIR}/clients/.session-N.json
# Records the identity + repo for an active client slot so `stop` knows what
# to tear down (ephemeral UUIDs are not predictable across runs).
# ---------------------------------------------------------------------------

def _session_file(cfg: config.Config, n: int):
    return cfg.version_dir / "ssh" / "clients" / f".session-{n}.json"


def _read_session(cfg: config.Config, n: int):
    path = _session_file(cfg, n)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _write_session(cfg: config.Config, n: int, user: str, repo_bare: str, ephemeral: bool) -> None:
    path = _session_file(cfg, n)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "slot": n,
        "user": user,
        "repo": repo_bare,
        "ephemeral": ephemeral,
        "started_at": int(time.time()),
    }, indent=2) + "\n")


def _delete_session(cfg: config.Config, n: int) -> None:
    _session_file(cfg, n).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# SSH key + ACL helpers
# ---------------------------------------------------------------------------

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


def _strip_user_from_acl(cfg: config.Config, user: str) -> int:
    """Remove ALL ACL entries for `user`. Returns the count stripped."""
    entries = _read_acl(cfg)
    kept = [e for e in entries if e[0] != user]
    removed = len(entries) - len(kept)
    if removed:
        _write_acl(cfg, kept)
    return removed


def _sync_register_and_grant(
    cfg: config.Config, user: str, repo_bare: str, perm: str = "+w", timeout: int = 15
) -> bool:
    """Eagerly register user + apply grant via svrAdmin, bypassing the 5s ACL sync window.

    The server's background scanner (entrypoint.sh) does the same work every 5s,
    but a brand-new ephemeral identity has to wait through that window before the
    client container can authenticate against the requested repo. Doing it
    synchronously here makes `gmcp client start` deterministic.

    Returns True if commands were issued and the ~admin/ queue drained within
    `timeout` seconds. Returns False (with no error) if the server container
    isn't running or queue drain timed out — the in-container retry loop in
    docker_only_ghidra_mcp_server.py is the backstop in those cases.
    """
    # 1. Pre-stage pubkey under /repos/~ssh/ so SSH auth works on first connect.
    src = cfg.version_dir / "ssh" / "clients" / user / "ssh_key.pub"
    if not src.is_file():
        return False
    dst_dir = cfg.version_dir / "repos" / "~ssh"
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst_dir / f"{user}.pub")

    # 2. Bail out if the server container isn't running; nothing to drive synchronously.
    probe = docker.docker_exec(cfg, SERVER_CONTAINER, ["true"], capture=True)
    if probe.returncode != 0:
        return False

    # 3. Queue add + grant. svrAdmin writes commands to /repos/~admin/*.cmd; the
    # server's command processor consumes them FIFO. -add for an existing user
    # exits non-zero — we don't care, the grant still applies.
    docker.docker_exec(cfg, SERVER_CONTAINER, [SVRADMIN, "-add", user], capture=True)
    docker.docker_exec(cfg, SERVER_CONTAINER, [SVRADMIN, "-grant", user, perm, repo_bare], capture=True)

    # 4. Wait for the queue to drain — server deletes the .cmd file once processed.
    admin_dir = cfg.version_dir / "repos" / "~admin"
    deadline = time.time() + timeout
    while time.time() < deadline:
        pending = list(admin_dir.glob("*.cmd")) if admin_dir.is_dir() else []
        if not pending:
            return True
        time.sleep(0.5)
    return False


def _wait_admin_queue(cfg: config.Config, timeout: int = 10) -> None:
    """Block until ~admin/*.cmd queue is drained (best-effort)."""
    admin_dir = cfg.version_dir / "repos" / "~admin"
    deadline = time.time() + timeout
    while time.time() < deadline:
        pending = list(admin_dir.glob("*.cmd")) if admin_dir.is_dir() else []
        if not pending:
            return
        time.sleep(0.5)


def _live_ephemeral_users(cfg: config.Config) -> set:
    """Return the set of ephemeral users currently bound to a running client container.

    A user is 'live' if there's a `.session-N.json` file naming it AND the
    container `ghidra-mcp-bridge-client-N` is actually up. Any ephemeral
    identity NOT in this set is stranded (its container crashed without
    `gmcp client stop`).
    """
    clients_dir = cfg.version_dir / "ssh" / "clients"
    if not clients_dir.is_dir():
        return set()
    live = set()
    for sf in clients_dir.glob(".session-*.json"):
        try:
            data = json.loads(sf.read_text())
        except Exception:
            continue
        user = data.get("user", "")
        slot = data.get("slot")
        if not user or slot is None:
            continue
        container = f"ghidra-mcp-bridge-client-{slot}"
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip() == "true":
            live.add(user)
    return live


def _release_stranded_ephemeral_locks(cfg: config.Config, repo_bare: str) -> int:
    """Force-release exclusive checkouts on `repo_bare` held by ephemeral
    users whose containers are no longer running.

    These accumulate when a container is SIGKILLed (OOM, host reboot, `docker
    kill`) without `gmcp client stop` — the server still records the lock
    as owned by a UUID nobody is using anymore, and any new client trying
    to open the same binary hits `checkout_conflict`. Two failure modes
    must be covered:

      1. SSH key dir still exists, container gone — disk-side iteration
         would find it, but doesn't generalize:
      2. SSH key dir was already pruned (prior `client stop` succeeded
         locally but its release-checkouts call silently failed against
         the server) yet the server-side lock persists.

    To catch both, we ask the server (via bridgectl) which users currently
    hold checkouts on this repo, cross-reference against `_live_ephemeral_
    users`, and release any ephemeral holder that's not live.

    Returns the total number of checkouts released.
    """
    probe = docker.docker_exec(cfg, SERVER_CONTAINER, ["true"], capture=True)
    if probe.returncode != 0:
        return 0  # Server not running, can't drive bridgectl

    holders = _list_repo_checkout_holders(cfg, repo_bare)
    if holders is None:
        return 0
    live = _live_ephemeral_users(cfg)

    # Identify which holders are stranded ephemerals (released as a group
    # per user, since `release-user-checkouts` is per-user not per-file).
    stranded_by_user = {}
    for user, folder, fname, cid in holders:
        if not _is_ephemeral_user(user):
            continue  # Leave named identities alone
        if user in live:
            continue
        stranded_by_user.setdefault(user, []).append(f"{folder.rstrip('/')}/{fname}")

    total = 0
    for user in sorted(stranded_by_user):
        files = stranded_by_user[user]
        output.info(
            f"Stranded ephemeral '{user}' held {len(files)} checkout(s) on {repo_bare}: "
            + ", ".join(files)
        )
        r = docker.admin_bootstrap(
            cfg, ["release-user-checkouts", user, repo_bare], capture=True
        )
        if r.returncode != 0:
            output.error(f"  Failed to release {user}: {(r.stderr or r.stdout or '').strip()}")
            continue
        for line in (r.stdout or "").splitlines():
            if line.startswith("total-released:"):
                try:
                    n = int(line.split(":", 1)[1])
                except ValueError:
                    continue
                if n > 0:
                    output.info(f"  Released {n} checkout(s) from {user}.")
                    total += n
    return total


def _list_repo_checkout_holders(cfg: config.Config, repo_bare: str):
    """Query bridgectl for every server-side checkout on `repo_bare`.

    Returns a list of `(user, folder, file, checkout_id)` tuples, or None
    if the server is unreachable. Empty list means no checkouts exist.
    """
    probe = docker.docker_exec(cfg, SERVER_CONTAINER, ["true"], capture=True)
    if probe.returncode != 0:
        return None
    r = docker.admin_bootstrap(
        cfg, ["list-checkout-holders", repo_bare], capture=True
    )
    if r.returncode != 0:
        return None
    holders = []
    for line in (r.stdout or "").splitlines():
        # Format: <user>:<folder>:<file>:<checkout_id>
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        user, folder, fname, cid = parts
        holders.append((user, folder, fname, cid))
    return holders


def _teardown_ephemeral_user(cfg: config.Config, user: str, repo_bare: str) -> None:
    """Fully remove an ephemeral identity from the server side.

    Must run AFTER the container has released its checkout — otherwise the
    server is left with a checkout owned by a now-deleted user.

    Order:
      1. Strip ACL entry  (so the entrypoint's 5s sync loop won't re-grant)
      2. Force-release any lingering server-side checkouts for this user
         (covers the SIGKILL-during-flush case where the container died with
         lock still held)
      3. svrAdmin -revoke
      4. svrAdmin -remove
      5. Wait for admin queue drain
      6. rm SSH private/public keys + repos/~ssh/<user>.pub
    """
    if not _is_ephemeral_user(user):
        output.info(f"Skipping teardown for non-ephemeral user '{user}' (would not auto-clean named identities).")
        return

    removed = _strip_user_from_acl(cfg, user)
    if removed:
        output.info(f"Stripped {removed} ACL entr(ies) for {user}.")

    # Force-release any orphan checkouts owned by this user. Best-effort:
    # admin_bootstrap needs the server running + bridgectl key, and may fail
    # for transient reasons; SSH key cleanup proceeds either way.
    probe = docker.docker_exec(cfg, SERVER_CONTAINER, ["true"], capture=True)
    if probe.returncode == 0:
        r = docker.admin_bootstrap(cfg, ["release-user-checkouts", user, repo_bare], capture=True)
        if r.returncode == 0:
            # stdout has `released:...` per lock + `total-released:N` summary
            tail = (r.stdout or "").strip().splitlines()[-1:] if r.stdout else []
            for line in tail:
                if line.startswith("total-released:") and not line.endswith(":0"):
                    output.info(f"Released orphan server-side checkout(s): {line}")
        else:
            output.info(
                f"Could not force-release checkouts for {user} via admin_bootstrap "
                f"(rc={r.returncode}); continuing teardown."
            )

        docker.docker_exec(cfg, SERVER_CONTAINER, [SVRADMIN, "-revoke", user, repo_bare], capture=True)
        docker.docker_exec(cfg, SERVER_CONTAINER, [SVRADMIN, "-remove", user], capture=True)
        _wait_admin_queue(cfg)

    udir = cfg.version_dir / "ssh" / "clients" / user
    if udir.exists():
        shutil.rmtree(udir, ignore_errors=True)
    pub = cfg.version_dir / "repos" / "~ssh" / f"{user}.pub"
    pub.unlink(missing_ok=True)
    output.info(f"Removed ephemeral user '{user}' (key + pubkey + svrAdmin entry).")


def _request_container_shutdown(http_port: int, timeout: float = 30.0) -> bool:
    """Hit /_shutdown on the client container so it can release checkout cleanly
    BEFORE docker stops it (the SIGTERM grace period is short).

    Returns True if the endpoint responded 2xx, False on any failure (including
    no listener — container may already be down).
    """
    url = f"http://127.0.0.1:{http_port}/_shutdown"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return False


def _poll_writable_status(http_port: int, timeout: float = 45.0):
    """Poll /api/status after container boot. Returns the `state` dict on first
    response with has_program=True (writable or not), or None on timeout.

    Container needs to load PyGhidra + connect to server + open program before
    /api/status reports has_program=True. That can take 30+ seconds on a cold
    JVM, hence the generous timeout.
    """
    url = f"http://127.0.0.1:{http_port}/api/status"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if 200 <= resp.status < 300:
                    body = json.loads(resp.read().decode("utf-8"))
                    state = body.get("state", {})
                    if state.get("has_program"):
                        return state
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError, ValueError):
            pass
        time.sleep(1.0)
    return None


def _wait_container_exit(container_name: str, timeout: float = 30.0) -> bool:
    """Poll `docker inspect` until the named container is gone or stopped."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return True  # Container doesn't exist anymore
        if r.stdout.strip() == "false":
            return True
        time.sleep(0.5)
    return False


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

    # Clean up any leftover ephemeral session from a prior crashed start on this slot.
    prior = _read_session(cfg, n)
    if prior is not None:
        prior_user = prior.get("user", "")
        prior_repo = prior.get("repo", repo_bare)
        if prior.get("ephemeral") and _is_ephemeral_user(prior_user):
            output.info(f"Found prior ephemeral session for slot {n} (user={prior_user}). Cleaning up before start.")
            _teardown_ephemeral_user(cfg, prior_user, prior_repo)
        _delete_session(cfg, n)

    # Release stranded checkouts from any OTHER ephemeral identity whose
    # container died without `gmcp client stop`. Otherwise the new client
    # below would hit `checkout_conflict` on its first write.
    _release_stranded_ephemeral_locks(cfg, repo_bare)

    # Resolve client identity
    if user_arg:
        user = user_arg
        if user in _RESERVED_USERS:
            output.error(f"User '{user}' is reserved.")
            raise click.Abort()
        if not _VALID_USER_RE.match(user):
            output.error(f"Invalid user name '{user}' (allowed: [A-Za-z0-9._-], 1-64 chars).")
            raise click.Abort()
        ephemeral = False
    else:
        user = f"{_EPHEMERAL_PREFIX}{_uuid.uuid4().hex[:12]}"
        ephemeral = True
        output.info(f"Ephemeral identity: {user}")

    # Generate SSH key (idempotent) + write +w grant (idempotent replace)
    _ensure_client_key(cfg, user)
    _grant_in_acl(cfg, user, repo_bare, "+w")
    if _sync_register_and_grant(cfg, user, repo_bare, "+w"):
        output.info(f"Granted {user} +w on {repo_bare} (synchronously applied).")
    else:
        output.info(f"Granted {user} +w on {repo_bare} (effective within ~5s via ACL sync).")

    import_name = ""
    if binary_file:
        import_name = binary or os.path.basename(binary_file)
        imports_dir = cfg.imports_dir
        staged_path = imports_dir / import_name
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary_file, staged_path)
        output.info(f"Binary staged: {binary_file} → {staged_path}")

    # Persist session metadata so `stop` knows which user to tear down.
    _write_session(cfg, n, user, repo_bare, ephemeral)

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
    click.echo(f"  User:    {user}{' (ephemeral)' if ephemeral else ''}")
    click.echo(f"  Repo:    {repo_bare}")
    click.echo(f"  Binary:  {binary or '(first available)'}")
    click.echo(f"  HTTP:    http://localhost:{http_port}")
    click.echo(f"  MCP SSE: http://localhost:{sse_port}/sse")

    # Wait for the program to load, then surface checkout-conflict warnings.
    # This catches the "admin GUI is editing the same binary" case loudly
    # rather than letting the user discover it via failed write API calls.
    output.info("Verifying checkout state (this can take ~30s on first start)...")
    state = _poll_writable_status(http_port)
    if state is None:
        output.info(
            "Could not confirm checkout state via /api/status. "
            f"Tail logs to debug: gmcp client logs {n}"
        )
    elif state.get("versioned") and not state.get("writable", True):
        holders = state.get("checkout_holders", [])
        named = [h["user"] for h in holders if h.get("kind") == "named-user"]
        ephem = [h["user"] for h in holders if h.get("kind") == "ephemeral-mcp"]
        click.echo()
        if named:
            output.error(
                f"⚠ MCP client {n} is READ-ONLY: '{named[0]}' holds the write lock "
                f"(likely via Ghidra GUI). Close it there, then: gmcp client stop {n} && gmcp client start {n} ..."
            )
        elif ephem:
            output.error(
                f"⚠ MCP client {n} is READ-ONLY: orphan MCP checkout from '{ephem[0]}'. "
                f"Run: gmcp client clean --all  then restart."
            )
        else:
            output.error(f"⚠ MCP client {n} is READ-ONLY: holder unknown. Check: gmcp client logs {n}")


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
def stop(n):
    """Stop client N and tear down its ephemeral identity (if any).

    Ordering matters: the container must release its server-side checkout
    BEFORE we delete the user — otherwise the server is left with a checkout
    owned by a vanished user.

    Steps:
      1. POST /_shutdown to the container (graceful checkin + exit)
      2. docker compose down  (SIGTERM fallback if /_shutdown was unreachable)
      3. If session.ephemeral: svrAdmin -revoke / -remove + strip ACL + rm SSH key
      4. Delete the session file
    """
    cfg = config.load()
    session = _read_session(cfg, n)
    http_port, _ = client_ports(n)

    # Step 1: graceful HTTP shutdown — container releases checkout itself.
    if _request_container_shutdown(http_port):
        output.info(f"Graceful shutdown signaled on :{http_port}; waiting for container exit...")
        _wait_container_exit(f"ghidra-mcp-bridge-client-{n}", timeout=30)
    else:
        output.info(f"Container on :{http_port} did not respond to /_shutdown (already down?).")

    # Step 2: compose down — covers the case where /_shutdown failed AND
    # ensures the docker-compose state is cleaned. SIGTERM fallback releases
    # checkout via the SIGTERM handler in docker_only_ghidra_mcp_server.py.
    docker.compose(
        cfg,
        ["down"],
        project=f"ghidra-client-{n}",
        file=COMPOSE_FILE,
    )

    # Step 3: tear down ephemeral identity (only if we created it).
    if session is not None:
        user = session.get("user", "")
        repo_bare = session.get("repo", "")
        if session.get("ephemeral") and _is_ephemeral_user(user) and repo_bare:
            _teardown_ephemeral_user(cfg, user, repo_bare)
        elif user and not _is_ephemeral_user(user):
            output.info(f"Preserving named identity '{user}' (use `gmcp server repo revoke` to drop access).")
        _delete_session(cfg, n)

    output.success(f"Client {n} stopped")


@client.command()
@click.argument("n", type=click.IntRange(1, 9), required=False)
@click.option("--all", "all_slots", is_flag=True, help="Clean every slot's leftover ephemeral identity.")
def clean(n, all_slots):
    """Tear down leftover ephemeral identities from crashed clients.

    Use this when a container died without `gmcp client stop` and left an
    orphan checkout / user on the server. Either pass N or --all.
    """
    cfg = config.load()
    if not n and not all_slots:
        output.error("Specify a slot number or --all.")
        raise click.Abort()

    targets = []
    if all_slots:
        clients_dir = cfg.version_dir / "ssh" / "clients"
        if clients_dir.is_dir():
            for sf in sorted(clients_dir.glob(".session-*.json")):
                try:
                    slot = int(sf.stem.split("-", 1)[1])
                    targets.append(slot)
                except ValueError:
                    continue
    else:
        targets = [n]

    if not targets:
        output.info("No leftover sessions found.")
        return

    for slot in targets:
        session = _read_session(cfg, slot)
        if session is None:
            output.info(f"Slot {slot}: no session file, skipping.")
            continue
        user = session.get("user", "")
        repo_bare = session.get("repo", "")
        if session.get("ephemeral") and _is_ephemeral_user(user) and repo_bare:
            output.info(f"Slot {slot}: tearing down ephemeral user '{user}' (repo={repo_bare})")
            _teardown_ephemeral_user(cfg, user, repo_bare)
        else:
            output.info(f"Slot {slot}: not ephemeral (user='{user}'), leaving identity in place.")
        _delete_session(cfg, slot)


@client.command()
@click.argument("n", type=click.IntRange(1, 9), required=False)
@click.option("--repo", "-r", default="", help="Repo to scan (overrides session file).")
def unstick(n, repo):
    """Release stranded checkouts blocking client N (or --repo) without restarting it.

    Use this when ghidra_edit / ghidra_exec returns `checkout_conflict` even
    though your client is alive: an earlier crashed container is still on
    the server's books as the lock holder. This walks every ephemeral
    identity with no live container and terminates its checkouts on the
    target repo via bridgectl. The live client picks up the released lock
    on its next write attempt — no `gmcp client stop` needed.
    """
    cfg = config.load()
    if not n and not repo:
        output.error("Specify a slot number (N) or --repo <name>.")
        raise click.Abort()

    if n:
        session = _read_session(cfg, n)
        if session is None and not repo:
            output.error(f"Slot {n} has no session file. Pass --repo to scan a specific repo.")
            raise click.Abort()
        repo_bare = (repo or session.get("repo", "")).lstrip("/")
    else:
        repo_bare = repo.lstrip("/")

    if not repo_bare:
        output.error("Could not determine target repo.")
        raise click.Abort()
    if not (cfg.version_dir / "repos" / repo_bare).is_dir():
        output.error(f"Repository '{repo_bare}' not found.")
        raise click.Abort()

    output.header(f"Releasing stranded checkouts on {repo_bare}...")
    total = _release_stranded_ephemeral_locks(cfg, repo_bare)
    if total == 0:
        output.success("No stranded checkouts found.")
    else:
        output.success(f"Released {total} stranded checkout(s). Retry your write — the live client should now succeed.")


@client.command()
@click.argument("n", type=click.IntRange(1, 9))
def logs(n):
    """Follow client N logs."""
    cfg = config.load()
    docker.docker_logs(cfg, f"ghidra-mcp-bridge-client-{n}")
