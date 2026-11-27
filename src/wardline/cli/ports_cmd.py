"""``wardline ports`` — CRUD expected listeners for ss_baseline."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from wardline.core.config import load_config, save_config
from wardline.core.ports import PortError, normalize_listener, parse_listener_list

ports_app = typer.Typer(help="Manage expected listening ports (scan.ss.expected_listeners).")


@ports_app.command("list")
def ports_list() -> None:
    """List expected listeners used by ss_baseline."""
    cfg = load_config()
    table = Table(title="Expected listeners", show_header=True, header_style="bold")
    table.add_column("#")
    table.add_column("Port/proto")
    for i, item in enumerate(cfg.scan.ss.expected_listeners, start=1):
        table.add_row(str(i), item)
    Console().print(table)


@ports_app.command("add")
def ports_add(
    port: str = typer.Argument(..., help="Port or port/proto (e.g. 22 or 53/udp)."),
) -> None:
    """Add an expected listener."""
    console = Console()
    cfg = load_config()
    try:
        norm = normalize_listener(port)
    except PortError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if norm in cfg.scan.ss.expected_listeners:
        console.print(f"[yellow]already present:[/yellow] {norm}")
        raise typer.Exit(code=0)
    cfg.scan.ss.expected_listeners.append(norm)
    path = save_config(cfg)
    console.print(f"[green]added[/green] {norm} → {path}")


@ports_app.command("remove")
def ports_remove(
    port: str = typer.Argument(..., help="Port or port/proto to remove."),
) -> None:
    """Remove an expected listener."""
    console = Console()
    cfg = load_config()
    try:
        norm = normalize_listener(port)
    except PortError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    before = list(cfg.scan.ss.expected_listeners)
    cfg.scan.ss.expected_listeners = [p for p in before if p != norm]
    if cfg.scan.ss.expected_listeners == before:
        console.print(f"[yellow]not found:[/yellow] {norm}")
        raise typer.Exit(code=1)
    path = save_config(cfg)
    console.print(f"[green]removed[/green] {norm} → {path}")


@ports_app.command("set")
def ports_set(
    ports: str = typer.Argument(
        ...,
        help='Comma-separated list replacing the full set, e.g. "22/tcp,80/tcp,443/tcp".',
    ),
) -> None:
    """Replace the entire expected-listeners list."""
    console = Console()
    cfg = load_config()
    try:
        cfg.scan.ss.expected_listeners = parse_listener_list(ports)
    except PortError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    path = save_config(cfg)
    console.print(
        f"[green]set[/green] {len(cfg.scan.ss.expected_listeners)} listener(s) → {path}"
    )
    for item in cfg.scan.ss.expected_listeners:
        console.print(f"  · {item}")
