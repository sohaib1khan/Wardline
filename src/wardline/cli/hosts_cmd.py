"""``wardline hosts`` — inventory, connectivity test, sudoers suggestion."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from wardline.backends.ssh import SSHBackend, SSHHostKeyError, accept_host_key
from wardline.core.hosts import (
    HostRecord,
    known_hosts_path,
    load_hosts,
    save_hosts,
    sudoers_suggestion,
)
from wardline.core.paths import hosts_file_path

hosts_app = typer.Typer(
    name="hosts",
    help="Manage remote SSH hosts (key auth, strict known_hosts).",
    no_args_is_help=True,
)


@hosts_app.command("list")
def hosts_list() -> None:
    """List hosts from hosts.toml."""
    console = Console()
    inventory = load_hosts()
    table = Table(title=f"Hosts ({hosts_file_path()})")
    table.add_column("Name")
    table.add_column("Host")
    table.add_column("User")
    table.add_column("Port")
    table.add_column("Tags")
    for host in inventory.hosts:
        table.add_row(
            host.name,
            host.host,
            host.user,
            str(host.port),
            ",".join(host.tags) if host.tags else "",
        )
    console.print(table)
    if not inventory.hosts:
        console.print(
            "[dim]No hosts yet. Copy hosts.example.toml to "
            f"{hosts_file_path()} or use `wardline hosts add`.[/dim]"
        )


@hosts_app.command("add")
def hosts_add(
    name: str = typer.Option(..., "--name", help="Short inventory name."),
    host: str = typer.Option(..., "--host", help="Hostname or IP."),
    user: str = typer.Option("wardline", "--user", "-u"),
    port: int = typer.Option(22, "--port", "-p"),
    identity_file: str | None = typer.Option(None, "--identity", "-i"),
    alias: str = typer.Option("", "--alias"),
    tags: str = typer.Option("", "--tags", help="Comma-separated tags."),
    use_sudo: bool = typer.Option(True, "--sudo/--no-sudo"),
) -> None:
    """Add a host to hosts.toml (never stores passwords)."""
    console = Console()
    inventory = load_hosts()
    try:
        inventory.get(name)
        console.print(f"[red]host {name!r} already exists[/red]")
        raise typer.Exit(code=1)
    except KeyError:
        pass
    record = HostRecord(
        name=name,
        host=host,
        user=user,
        port=port,
        identity_file=identity_file,
        alias=alias,
        tags=[t.strip() for t in tags.split(",") if t.strip()],
        use_sudo=use_sudo,
    )
    inventory.hosts.append(record)
    path = save_hosts(inventory)
    console.print(f"[green]Added[/green] {name} → {path}")


@hosts_app.command("test")
def hosts_test(name: str = typer.Argument(..., help="Host name or alias.")) -> None:
    """Test SSH connectivity (strict known_hosts)."""
    console = Console()
    inventory = load_hosts()
    try:
        record = inventory.get(name)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    async def _go() -> int:
        backend = SSHBackend(record)
        try:
            info = await backend.host_info()
            console.print(
                f"[green]OK[/green] {record.name} · {info.hostname} · "
                f"{info.distro} {info.version} · root={'yes' if info.is_root else 'no'}"
            )
            return 0
        except SSHHostKeyError as exc:
            console.print(f"[red]Host key error:[/red] {exc}")
            if exc.fingerprint:
                console.print(f"Fingerprint: [bold]{exc.fingerprint}[/bold]")
            if exc.unknown:
                console.print(
                    f"If this matches the expected key, run:\n"
                    f"  wardline hosts accept-key {record.name}"
                )
            return 1
        except Exception as exc:
            console.print(f"[red]Connection failed:[/red] {exc}")
            return 1
        finally:
            await backend.close()

    raise typer.Exit(code=asyncio.run(_go()))


@hosts_app.command("accept-key")
def hosts_accept_key(
    name: str = typer.Argument(..., help="Host name or alias."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirm."),
) -> None:
    """Fetch and save the server host key after you confirm the fingerprint."""
    console = Console()
    inventory = load_hosts()
    try:
        record = inventory.get(name)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    async def _go() -> int:
        from wardline.backends.ssh import fetch_host_key_fingerprint

        try:
            fingerprint, _ = await fetch_host_key_fingerprint(record.host, port=record.port)
        except Exception as exc:
            console.print(f"[red]Could not fetch host key:[/red] {exc}")
            return 1
        console.print(f"Host: {record.host}:{record.port}")
        console.print(f"Fingerprint: [bold]{fingerprint}[/bold]")
        console.print(f"Will append to {known_hosts_path()}")
        if not yes:
            confirmed = typer.confirm("Save this host key?", default=False)
            if not confirmed:
                console.print("[yellow]Cancelled[/yellow]")
                return 1
        fp = await accept_host_key(record.host, port=record.port)
        console.print(f"[green]Saved[/green] host key ({fp})")
        return 0

    raise typer.Exit(code=asyncio.run(_go()))


@hosts_app.command("sudoers")
def hosts_sudoers(
    user: str = typer.Option("wardline", "--user", "-u"),
) -> None:
    """Print a suggested sudoers allowlist (never applied automatically)."""
    console = Console()
    console.print(sudoers_suggestion(user=user))


@hosts_app.command("path")
def hosts_path() -> None:
    """Show the hosts.toml and known_hosts paths."""
    console = Console()
    console.print(f"hosts.toml:    {hosts_file_path()}")
    console.print(f"known_hosts:   {known_hosts_path()}")
