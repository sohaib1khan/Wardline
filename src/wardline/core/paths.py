"""Config and data directory resolution (XDG for user, FHS for root)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600

ENV_CONFIG_DIR = "WARDLINE_CONFIG_DIR"
ENV_DATA_DIR = "WARDLINE_DATA_DIR"


def _is_root() -> bool:
    return os.geteuid() == 0


def _xdg_config_home() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME")
    if raw:
        return Path(raw)
    return Path.home() / ".config"


def _xdg_data_home() -> Path:
    raw = os.environ.get("XDG_DATA_HOME")
    if raw:
        return Path(raw)
    return Path.home() / ".local" / "share"


def get_config_dir() -> Path:
    """Return the Wardline config directory (does not create it)."""
    override = os.environ.get(ENV_CONFIG_DIR)
    if override:
        return Path(override).expanduser().resolve()
    if _is_root():
        return Path("/etc/wardline")
    return _xdg_config_home() / "wardline"


def get_data_dir() -> Path:
    """Return the Wardline data directory (does not create it)."""
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override).expanduser().resolve()
    if _is_root():
        return Path("/var/lib/wardline")
    return _xdg_data_home() / "wardline"


def ensure_dir(path: Path, mode: int = DIR_MODE) -> Path:
    """Create a directory with restrictive permissions if missing."""
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    # mkdir mode is masked by umask; force the intended mode.
    path.chmod(mode)
    return path


def ensure_file_perms(path: Path, mode: int = FILE_MODE) -> Path:
    """Set file permissions if the path exists and is a regular file."""
    if path.is_file() and not path.is_symlink():
        path.chmod(mode)
    return path


def write_private_file(path: Path, data: str | bytes, mode: int = FILE_MODE) -> Path:
    """Write a file and set mode 0600. Parent must already exist or be creatable."""
    ensure_dir(path.parent)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    path.chmod(mode)
    return path


def ensure_data_layout(data_dir: Path | None = None) -> Path:
    """Create the standard data dir layout with 0700 directories.

    Layout::

        <data>/
        ├── vault/
        │   └── .trash/
        ├── evidence/
        ├── cache/
        └── logs/
    """
    root = data_dir if data_dir is not None else get_data_dir()
    ensure_dir(root)
    ensure_dir(root / "vault")
    ensure_dir(root / "vault" / ".trash")
    ensure_dir(root / "evidence")
    ensure_dir(root / "cache")
    ensure_dir(root / "logs")
    return root


def vault_root(data_dir: Path | None = None) -> Path:
    root = ensure_data_layout(data_dir)
    return root / "vault"


def evidence_root(data_dir: Path | None = None) -> Path:
    root = ensure_data_layout(data_dir)
    return root / "evidence"


def cache_root(data_dir: Path | None = None) -> Path:
    root = ensure_data_layout(data_dir)
    return root / "cache"


def log_file_path(data_dir: Path | None = None) -> Path:
    root = ensure_data_layout(data_dir)
    return root / "logs" / "wardline.log"


def config_file_path(config_dir: Path | None = None) -> Path:
    base = config_dir if config_dir is not None else get_config_dir()
    return base / "config.toml"


def hosts_file_path(config_dir: Path | None = None) -> Path:
    base = config_dir if config_dir is not None else get_config_dir()
    return base / "hosts.toml"


def describe_storage_layout(*, data_dir: Path | None = None, config_dir: Path | None = None) -> str:
    """Human-readable where Wardline stores config, reports, and evidence."""
    cfg = config_dir if config_dir is not None else get_config_dir()
    data = data_dir if data_dir is not None else get_data_dir()
    lines = [
        f"Config dir     {cfg}",
        f"  config.toml  {cfg / 'config.toml'}",
        f"  hosts.toml   {cfg / 'hosts.toml'}",
        f"Data dir       {data}",
        f"  Vault        {data / 'vault'}  (scan.json, report.md/html, raw/)",
        f"  Evidence     {data / 'evidence'}",
        f"  Cache        {data / 'cache'}",
        f"  Logs         {data / 'logs' / 'wardline.log'}",
        "",
        "Overrides: WARDLINE_CONFIG_DIR · WARDLINE_DATA_DIR",
        "Permissions: directories 0700 · files 0600",
    ]
    return "\n".join(lines)


def mode_octal(path: Path) -> int:
    """Return permission bits (e.g. 0o700) for tests and diagnostics."""
    return stat.S_IMODE(path.stat().st_mode)
