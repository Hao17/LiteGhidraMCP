from __future__ import annotations

import shutil
import subprocess
import sys

from cli.config import Config


def _compose_cmd() -> list[str]:
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return ["docker", "compose"]


def compose(
    cfg: Config,
    args: list[str],
    *,
    file: str | None = None,
    project: str | None = None,
    env_overrides: dict[str, str] | None = None,
    capture: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess:
    cmd = _compose_cmd()
    if project:
        cmd += ["-p", project]
    if file:
        cmd += ["-f", file]
    cmd += args

    kwargs: dict = dict(
        cwd=str(cfg.docker_dir),
        env=cfg.full_env(env_overrides),
    )
    if capture or quiet:
        kwargs["capture_output"] = True
        kwargs["text"] = True

    return subprocess.run(cmd, **kwargs)


def docker_exec(
    cfg: Config,
    container: str,
    cmd: list[str],
    *,
    interactive: bool = False,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    full_cmd = ["docker", "exec"]
    if interactive:
        full_cmd += ["-it"]
    full_cmd += [container] + cmd

    kwargs: dict = dict(cwd=str(cfg.docker_dir), env=cfg.full_env())
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True

    return subprocess.run(full_cmd, **kwargs)


def docker_logs(
    cfg: Config,
    container: str,
) -> None:
    try:
        subprocess.run(
            ["docker", "logs", container, "-f"],
            cwd=str(cfg.docker_dir),
            env=cfg.full_env(),
        )
    except KeyboardInterrupt:
        pass


def run_script(cfg: Config, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=str(cfg.docker_dir),
        env=cfg.full_env(),
    )


def admin_bootstrap(
    cfg: Config,
    args: list[str],
    *,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """Run scripts/admin_bootstrap.py one-shot inside the bridge image as bridgectl.

    Requires bridgectl SSH key at ${GHIDRA_DATA_DIR}/${GHIDRA_VERSION}/ssh/clients/bridgectl/.
    """
    ssh_dir = cfg.version_dir / "ssh"
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "ghidra-shared-network",
        "-v", f"{ssh_dir}:/ssh:ro",
        "-e", "GHIDRA_SERVER_HOST=ghidra-server",
        "-e", f"GHIDRA_SERVER_PORT={cfg.server_port}",
        "-e", "GHIDRA_SERVER_USER=bridgectl",
        "-e", "GHIDRA_SERVER_KEYSTORE=/ssh/clients/bridgectl/ssh_key",
        "--entrypoint", "python3",
        "ghidra-mcp-bridge:latest",
        "/app/scripts/admin_bootstrap.py",
        *args,
    ]
    kwargs: dict = dict(cwd=str(cfg.docker_dir), env=cfg.full_env())
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    return subprocess.run(docker_cmd, **kwargs)
