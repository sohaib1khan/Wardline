"""``wardline tools`` — show / install scanner dependencies for this distro."""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass

import typer
from rich.console import Console
from rich.table import Table

from wardline.backends.local import LocalBackend
from wardline.core.distro import DistroInfo, detect_distro
from wardline.plugins.base import Plugin, get_registry

tools_app = typer.Typer(help="Detect and install scanner tools for this host.")


@dataclass(slots=True)
class ToolPlan:
    plugin: str
    status: str
    version: str | None
    commands: list[str]


@tools_app.command("list")
def tools_list(
    missing_only: bool = typer.Option(
        False,
        "--missing",
        help="Only show tools that are not installed.",
    ),
) -> None:
    """List plugin tool status and install hints for this distro."""
    console = Console()
    plans = asyncio.run(_collect_plans())
    table = Table(title="Scanner tools", show_header=True, header_style="bold")
    table.add_column("Plugin")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Install hint")
    shown = 0
    for plan in plans:
        if missing_only and plan.status != "missing":
            continue
        shown += 1
        hint = plan.commands[0] if plan.commands else "—"
        table.add_row(plan.plugin, plan.status, plan.version or "—", hint)
    if shown == 0:
        console.print("[green]No missing tools.[/green]" if missing_only else "No plugins.")
        return
    console.print(table)
    console.print(
        "\n[dim]Run [bold]wardline tools install[/bold] to execute install commands "
        "after confirmation.[/dim]"
    )


@tools_app.command("install")
def tools_install(
    names: list[str] | None = typer.Argument(
        None,
        help="Plugin names to install (default: all missing).",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Run install commands without an interactive prompt.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print commands only; do not execute.",
    ),
) -> None:
    """Show install commands for missing tools and run them after confirmation.

    Safety: commands are printed first. Without --yes you must type 'install'.
    """
    console = Console()
    code = asyncio.run(_install_async(console, names=names, yes=yes, dry_run=dry_run))
    raise typer.Exit(code=code)


async def _collect_plans() -> list[ToolPlan]:
    backend = LocalBackend()
    distro = await asyncio.to_thread(detect_distro)
    registry = get_registry()
    plans: list[ToolPlan] = []
    for plugin in registry.list(include_hidden=False):
        plan = await _plan_for(plugin, backend, distro)
        plans.append(plan)
    return plans


async def _plan_for(plugin: Plugin, backend: LocalBackend, distro: DistroInfo) -> ToolPlan:
    detect = await plugin.detect(backend)
    if detect.denylisted:
        return ToolPlan(
            plugin=plugin.name,
            status="denylisted",
            version=detect.version,
            commands=[],
        )
    if detect.installed:
        return ToolPlan(
            plugin=plugin.name,
            status="ok",
            version=detect.version,
            commands=[],
        )
    hints = [h for h in plugin.install_hint(distro) if h.strip() and not h.strip().startswith("#")]
    return ToolPlan(
        plugin=plugin.name,
        status="missing",
        version=detect.version,
        commands=hints,
    )


async def _install_async(
    console: Console,
    *,
    names: list[str] | None,
    yes: bool,
    dry_run: bool,
) -> int:
    plans = await _collect_plans()
    wanted = {n.strip().lower() for n in (names or []) if n.strip()}
    selected = [
        p
        for p in plans
        if p.status == "missing"
        and p.commands
        and (not wanted or p.plugin in wanted)
    ]
    if wanted:
        known = {p.plugin for p in plans}
        unknown = wanted - known
        if unknown:
            console.print(f"[red]Unknown plugin(s):[/red] {', '.join(sorted(unknown))}")
            return 2

    if not selected:
        console.print("[green]Nothing to install[/green] — missing tools already present, or no hints.")
        return 0

    console.print("[bold]Install plan[/bold] (shown before any execution):\n")
    commands: list[str] = []
    for plan in selected:
        console.print(f"  [cyan]{plan.plugin}[/cyan]")
        for cmd in plan.commands:
            console.print(f"    $ {cmd}")
            commands.append(cmd)
    console.print()

    if dry_run:
        console.print("[dim]Dry run — no commands executed.[/dim]")
        return 0

    if not yes:
        answer = typer.prompt("Type 'install' to run these commands", default="")
        if answer.strip().lower() != "install":
            console.print("[yellow]Cancelled.[/yellow]")
            return 1

    failures = 0
    for cmd in commands:
        console.print(f"\n[bold]$ {cmd}[/bold]")
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                shell=True,
                check=False,
            )
        except OSError as exc:
            console.print(f"[red]failed to spawn:[/red] {exc}")
            failures += 1
            continue
        if completed.returncode != 0:
            console.print(f"[red]exit {completed.returncode}[/red]")
            failures += 1
        else:
            console.print("[green]ok[/green]")

    console.print()
    if failures:
        console.print(f"[yellow]Finished with {failures} failure(s).[/yellow] Re-run doctor.")
        return 1
    console.print("[green]Done.[/green] Run [bold]wardline doctor[/bold] to verify.")
    return 0
