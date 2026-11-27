"""Remote host inventory (``hosts.toml`` in the config directory)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from wardline.core.paths import (
    DIR_MODE,
    ensure_dir,
    get_config_dir,
    hosts_file_path,
    write_private_file,
)

try:
    import tomli_w
except ImportError:  # pragma: no cover
    tomli_w = None  # type: ignore[assignment]


class HostRecord(BaseModel):
    """One remote host entry from hosts.toml."""

    name: str
    host: str
    user: str = "wardline"
    port: int = 22
    identity_file: str | None = None
    alias: str = ""
    tags: list[str] = Field(default_factory=list)
    use_sudo: bool = True

    @field_validator("name", "host", "user")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("port")
    @classmethod
    def _valid_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("port must be 1-65535")
        return value

    def display_name(self) -> str:
        return self.alias or self.name

    def resolve_identity(self, config_dir: Path | None = None) -> Path | None:
        if not self.identity_file:
            return None
        raw = Path(self.identity_file).expanduser()
        if raw.is_absolute():
            return raw
        base = config_dir if config_dir is not None else get_config_dir()
        return (base / raw).resolve()


class HostInventory(BaseModel):
    hosts: list[HostRecord] = Field(default_factory=list)
    fleet_concurrency: int = 4

    @field_validator("fleet_concurrency")
    @classmethod
    def _concurrency(cls, value: int) -> int:
        if value < 1:
            raise ValueError("fleet_concurrency must be >= 1")
        return value

    def get(self, name: str) -> HostRecord:
        key = name.strip().lower()
        for host in self.hosts:
            if host.name.lower() == key or host.alias.lower() == key:
                return host
        raise KeyError(f"unknown host {name!r}")

    def names(self) -> list[str]:
        return [h.name for h in self.hosts]


def load_hosts(path: Path | None = None, *, missing_ok: bool = True) -> HostInventory:
    cfg_path = path if path is not None else hosts_file_path()
    if not cfg_path.exists():
        if missing_ok:
            return HostInventory()
        raise FileNotFoundError(
            f"hosts file not found: {cfg_path}. Copy hosts.example.toml and edit it."
        )
    raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("hosts.toml root must be a table")
    # Allow top-level fleet_concurrency + [[hosts]]
    return HostInventory.model_validate(raw)


def save_hosts(inventory: HostInventory, path: Path | None = None) -> Path:
    if tomli_w is None:  # pragma: no cover
        raise RuntimeError("tomli-w is required to write hosts.toml")
    cfg_path = path if path is not None else hosts_file_path()
    ensure_dir(cfg_path.parent, mode=DIR_MODE)
    payload = {
        "fleet_concurrency": inventory.fleet_concurrency,
        "hosts": [h.model_dump(exclude_none=True) for h in inventory.hosts],
    }
    text = tomli_w.dumps(payload)
    write_private_file(cfg_path, text)
    return cfg_path


def known_hosts_path(config_dir: Path | None = None) -> Path:
    base = config_dir if config_dir is not None else get_config_dir()
    return base / "known_hosts"


def ensure_known_hosts_file(path: Path | None = None) -> Path:
    target = path if path is not None else known_hosts_path()
    ensure_dir(target.parent, mode=DIR_MODE)
    if not target.exists():
        write_private_file(target, "")
    return target


def sudoers_suggestion(*, user: str = "wardline") -> str:
    """Print-only sudoers allowlist for a dedicated scanner user."""
    binaries = [
        "/usr/sbin/ss",
        "/usr/bin/ss",
        "/usr/sbin/lynis",
        "/usr/bin/lynis",
        "/usr/local/bin/trivy",
        "/usr/bin/trivy",
        "/usr/bin/clamscan",
        "/usr/bin/rkhunter",
        "/usr/sbin/chkrootkit",
        "/usr/bin/chkrootkit",
        "/usr/bin/aide",
        "/usr/sbin/aide",
        "/usr/bin/nmap",
        "/usr/bin/oscap",
        "/usr/bin/debsums",
        "/usr/bin/rpm",
        "/usr/sbin/needrestart",
        "/usr/bin/needs-restarting",
        "/usr/bin/python3",
        "/bin/cat",
        "/usr/bin/test",
        "/usr/bin/which",
        "/bin/sh",
    ]
    # Cmnd_Alias style suggestion — never applied automatically.
    lines = [
        f"# Suggested sudoers fragment for dedicated user `{user}`",
        "# Review carefully before installing. Wardline never edits sudoers itself.",
        "# Install example: sudo visudo -f /etc/sudoers.d/wardline",
        "",
        f"Cmnd_Alias WARDLINE_SCAN = {', '.join(binaries)}",
        f"{user} ALL=(root) NOPASSWD: WARDLINE_SCAN",
        "",
    ]
    return "\n".join(lines)
