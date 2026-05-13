from __future__ import annotations

import os
import sys
from pathlib import Path

import click


class Config:
    def __init__(self, docker_dir: Path, env: dict[str, str]):
        self.docker_dir = docker_dir
        self.env = env

    @property
    def ghidra_data_dir(self) -> str:
        return self.env.get("GHIDRA_DATA_DIR", "")

    @property
    def ghidra_version(self) -> str:
        return self.env.get("GHIDRA_VERSION", "12.0.3")

    @property
    def server_port(self) -> int:
        return int(self.env.get("GHIDRA_SERVER_PORT", "13100"))

    @property
    def version_dir(self) -> Path:
        return Path(self.ghidra_data_dir) / self.ghidra_version

    @property
    def imports_dir(self) -> Path:
        return self.version_dir / "imports"

    def full_env(self, overrides: dict[str, str] | None = None) -> dict[str, str]:
        merged = os.environ.copy()
        merged.update(self.env)
        if overrides:
            merged.update(overrides)
        return merged

    def ensure_data_dirs(self):
        if not self.ghidra_data_dir:
            click.echo(click.style("ERROR: GHIDRA_DATA_DIR not set in docker/.env", fg="red"), err=True)
            sys.exit(1)
        base = Path(self.ghidra_data_dir)
        base.mkdir(parents=True, exist_ok=True)
        for sub in ["repos", "config", "ssh/clients", "imports"]:
            (self.version_dir / sub).mkdir(parents=True, exist_ok=True)
        logs_dir = base / "logs" / self.ghidra_version
        logs_dir.mkdir(parents=True, exist_ok=True)


def find_docker_dir() -> Path:
    # If we're inside the project, walk up to find docker/Makefile
    cwd = Path.cwd()
    for d in [cwd, *cwd.parents]:
        candidate = d / "docker" / "Makefile"
        if candidate.is_file():
            return d / "docker"
    # Maybe cwd IS the docker dir
    if (cwd / "Makefile").is_file() and (cwd / "docker-compose.server.yml").is_file():
        return cwd
    # Last resort: relative to this package (installed via pip install -e .)
    pkg_root = Path(__file__).resolve().parent.parent
    candidate = pkg_root / "docker" / "Makefile"
    if candidate.is_file():
        return pkg_root / "docker"
    click.echo(click.style("ERROR: Cannot find docker/ directory. Run gmcp from the project tree.", fg="red"), err=True)
    sys.exit(1)


def _parse_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        env[key] = value
    return env


_DEFAULT_ENV = {
    "GHIDRA_DATA_DIR": str(Path.home() / "ghidra-data"),
    "GHIDRA_VERSION": "12.0.3",
    "GHIDRA_SERVER_PORT": "13100",
}


def _ensure_env(docker_dir: Path) -> None:
    env_file = docker_dir / ".env"
    if env_file.is_file():
        return
    lines = [
        "# Ghidra MCP Bridge (auto-generated)",
        f"GHIDRA_DATA_DIR={_DEFAULT_ENV['GHIDRA_DATA_DIR']}",
        f"GHIDRA_VERSION={_DEFAULT_ENV['GHIDRA_VERSION']}",
        f"GHIDRA_SERVER_PORT={_DEFAULT_ENV['GHIDRA_SERVER_PORT']}",
        "",
    ]
    env_file.write_text("\n".join(lines))
    click.echo(f"Created {env_file} with defaults (data: {_DEFAULT_ENV['GHIDRA_DATA_DIR']})")


def load() -> Config:
    docker_dir = find_docker_dir()
    _ensure_env(docker_dir)
    env = _parse_env(docker_dir / ".env")
    return Config(docker_dir, env)
