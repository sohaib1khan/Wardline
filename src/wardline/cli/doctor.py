"""``wardline doctor`` — host readiness and plugin detection table."""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.table import Table

from wardline import __version__
from wardline.backends.local import LocalBackend, read_total_ram_mb
from wardline.core.distro import DistroInfo, detect_distro
from wardline.plugins.base import Plugin, get_registry


def run_doctor(*, console: Console | None = None) -> int:
    """Print a readiness report. Returns process exit code (0 = ok)."""
    console = console or Console()
    return asyncio.run(_doctor_async(console))


async def _doctor_async(console: Console) -> int:
    backend = LocalBackend()

    try:
        distro = await asyncio.to_thread(detect_distro)
    except (FileNotFoundError, OSError) as exc:
        console.print(f"[red]distro detection failed:[/red] {exc}")
        return 2

    host = await backend.host_info()
    ram = host.ram_mb if host.ram_mb is not None else await asyncio.to_thread(read_total_ram_mb)

    from wardline.meta import REPO_URL

    console.print(f"[bold]Wardline[/bold] {__version__}  ·  doctor")
    console.print(f"[dim]{REPO_URL}[/dim]")
    console.print()

    sys_table = Table(title="Host", show_header=True, header_style="bold")
    sys_table.add_column("Field")
    sys_table.add_column("Value")
    sys_table.add_row("Hostname", host.hostname)
    sys_table.add_row("Distro", f"{distro.pretty_name} ({distro.id})")
    sys_table.add_row("Family", distro.family)
    sys_table.add_row("Package manager", distro.package_manager.value)
    sys_table.add_row("Kernel", host.kernel)
    sys_table.add_row("Arch", host.arch)
    sys_table.add_row("RAM", f"{ram} MiB" if ram is not None else "unknown")
    sys_table.add_row("Root", "yes" if backend.is_root() else "no")
    sys_table.add_row("Backend", backend.kind.value)
    console.print(sys_table)
    console.print()

    registry = get_registry()
    plugins = registry.list(include_hidden=False)
    hidden_count = len(registry.list(include_hidden=True)) - len(plugins)

    tools = Table(title="Plugins", show_header=True, header_style="bold")
    tools.add_column("Plugin")
    tools.add_column("Status")
    tools.add_column("Version")
    tools.add_column("Root")
    tools.add_column("Notes")

    if not plugins:
        tools.add_row(
            "—",
            "none registered",
            "—",
            "—",
            "real scanners arrive in Phase 3+",
        )
    else:
        for plugin in plugins:
            status, version, notes = await _detect_row(plugin, backend, distro)
            tools.add_row(
                plugin.display_name,
                status,
                version or "—",
                "yes" if plugin.needs_root else "no",
                notes or "",
            )

    console.print(tools)
    if hidden_count:
        console.print(
            f"[dim]({hidden_count} hidden/dev plugin(s) registered, omitted from table)[/dim]"
        )
    console.print()
    console.print(
        "[dim]Tip: [bold]wardline guide[/bold] · "
        "[bold]wardline tools list --missing[/bold] · "
        "[bold]wardline tools install[/bold] (confirm before run).[/dim]"
    )
    return 0


async def _detect_row(
    plugin: Plugin,
    backend: LocalBackend,
    distro: DistroInfo,
) -> tuple[str, str | None, str]:
    detect = await plugin.detect(backend)
    if detect.denylisted:
        return "DENYLISTED", detect.version, detect.denylist_reason or "denylisted"
    if not detect.installed:
        hints = plugin.install_hint(distro)
        hint = hints[0] if hints else "not installed"
        return "missing", detect.version, hint
    return "ok", detect.version, detect.detail
