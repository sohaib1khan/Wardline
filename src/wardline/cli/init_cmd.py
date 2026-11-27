"""``wardline init`` — create config + data directories for a fresh install."""

from __future__ import annotations

import shutil
from pathlib import Path

from rich.console import Console

from wardline.core.config import ensure_config_dir, ensure_user_config
from wardline.core.paths import (
    config_file_path,
    describe_storage_layout,
    ensure_data_layout,
    get_config_dir,
    get_data_dir,
    hosts_file_path,
)
from wardline.meta import REPO_URL


def run_init(*, force: bool = False, console: Console | None = None) -> int:
    """Create Wardline dirs and seed example config/hosts if missing."""
    console = console or Console()
    cfg_dir = ensure_config_dir()
    data = ensure_data_layout()
    cfg_path = config_file_path()
    hosts_path = hosts_file_path()

    if cfg_path.exists() and not force:
        console.print(f"[green]config exists[/green]  {cfg_path}")
    else:
        ensure_user_config(force_defaults=force)
        console.print(f"[green]wrote[/green]  {cfg_path}")

    if hosts_path.exists() and not force:
        console.print(f"[green]hosts exists[/green]  {hosts_path}")
    else:
        example = _repo_example("hosts.example.toml")
        if example is not None:
            shutil.copyfile(example, hosts_path)
            hosts_path.chmod(0o600)
            console.print(f"[green]wrote[/green]  {hosts_path} (from hosts.example.toml)")
        else:
            hosts_path.write_text(
                '# Wardline hosts inventory\n# [[hosts]]\n# name = "lab01"\n'
                '# host = "192.0.2.10"\n# user = "wardline"\n# port = 22\n',
                encoding="utf-8",
            )
            hosts_path.chmod(0o600)
            console.print(f"[green]wrote[/green]  {hosts_path}")

    console.print()
    console.print("[bold]Storage layout[/bold]")
    console.print(describe_storage_layout(data_dir=data, config_dir=cfg_dir))
    console.print()
    console.print(f"[dim]App:[/dim]  {REPO_URL}")
    console.print(
        "[dim]Next:[/dim]  wardline guide  ·  wardline doctor  ·  wardline tools install  ·  wardline"
    )
    console.print(f"[dim]Config root: {get_config_dir()} · Data root: {get_data_dir()}[/dim]")
    return 0


def _repo_example(name: str) -> Path | None:
    # src/wardline/cli/init_cmd.py → repo root
    root = Path(__file__).resolve().parents[3]
    candidate = root / name
    return candidate if candidate.is_file() else None
