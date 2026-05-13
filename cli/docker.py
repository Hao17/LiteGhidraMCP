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
) -> subprocess.CompletedProcess:
    full_cmd = ["docker", "exec"]
    if interactive:
        full_cmd += ["-it"]
    full_cmd += [container] + cmd

    return subprocess.run(
        full_cmd,
        cwd=str(cfg.docker_dir),
        env=cfg.full_env(),
    )


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
