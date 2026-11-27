"""``wardline vault`` subcommands."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from wardline.reports.html import render_html
from wardline.reports.json_report import render_json
from wardline.reports.markdown import render_markdown
from wardline.vault.diff import DiffKind, diff_scans
from wardline.vault.safety import VaultSafetyError
from wardline.vault.store import VaultStore

vault_app = typer.Typer(
    name="vault",
    help="Browse, export, tag, and soft-delete saved scans.",
    no_args_is_help=True,
)


@vault_app.command("list")
def vault_list(
    host: str | None = typer.Option(None, "--host", help="Filter by hostname."),
    profile: str | None = typer.Option(None, "--profile", help="Filter by profile."),
    tag: str | None = typer.Option(None, "--tag", help="Filter by tag."),
    limit: int = typer.Option(50, "--limit", help="Max rows."),
) -> None:
    """List scans in the Vault."""
    console = Console()
    store = VaultStore()
    entries = store.list_scans(host=host, profile=profile, tag=tag, limit=limit)
    table = Table(title="Vault", show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Host")
    table.add_column("When")
    table.add_column("Profile")
    table.add_column("Posture")
    table.add_column("C/H/M/L/I")
    table.add_column("Tags")
    for entry in entries:
        short = entry.scan_id[-10:]
        table.add_row(
            short,
            entry.host,
            entry.started_at.replace("T", " ")[:16],
            entry.profile,
            str(entry.posture),
            f"{entry.critical}/{entry.high}/{entry.medium}/{entry.low}/{entry.info}",
            ",".join(entry.tags) if entry.tags else "",
        )
    console.print(table)
    if not entries:
        console.print("[dim]Vault is empty. Run `wardline scan` to save a report.[/dim]")


@vault_app.command("show")
def vault_show(
    scan_id: str = typer.Argument(..., help="Full scan id or unique suffix."),
) -> None:
    """Show a saved scan summary."""
    console = Console()
    store = VaultStore()
    try:
        scan = store.load_scan(scan_id)
        entry = store.get_entry(scan.id)
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"[bold]{scan.host.hostname}[/bold]  scan={scan.id}")
    console.print(f"profile={scan.profile} posture={scan.scores.posture} path={entry.path}")
    sev = scan.summary.by_severity
    console.print(
        f"findings: critical={sev.critical} high={sev.high} "
        f"medium={sev.medium} low={sev.low} info={sev.info}"
    )
    for finding in scan.findings[:20]:
        console.print(f"  [{finding.severity.value}] {finding.plugin}: {finding.title}")


@vault_app.command("export")
def vault_export(
    scan_id: str = typer.Argument(...),
    fmt: str = typer.Option("html", "--format", "-f", help="json | md | html"),
    redact: bool = typer.Option(False, "--redact", help="Mask IPs/host/usernames."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to file instead of stdout."
    ),
) -> None:
    """Export a report (optionally redacted)."""
    console = Console()
    store = VaultStore()
    try:
        scan = store.load_scan(scan_id)
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    fmt_l = fmt.lower()
    if fmt_l == "json":
        text = render_json(scan, redact=redact)
    elif fmt_l in {"md", "markdown"}:
        text = render_markdown(scan, redact=redact)
    elif fmt_l == "html":
        text = render_html(scan, redact=redact)
    else:
        console.print(f"[red]unknown format {fmt!r}[/red]")
        raise typer.Exit(code=2)

    if output is not None:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        # Avoid Rich markup interpretation for raw HTML/MD.
        print(text, end="")


@vault_app.command("tag")
def vault_tag(
    scan_id: str = typer.Argument(...),
    tag: str = typer.Argument(..., help="Tag to add."),
) -> None:
    """Add a tag to a saved scan."""
    console = Console()
    store = VaultStore()
    try:
        tags = store.add_tag(scan_id, tag)
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"tags: {', '.join(tags)}")


@vault_app.command("delete")
def vault_delete(
    scan_id: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirm."),
    confirm: str | None = typer.Option(
        None,
        "--confirm",
        help="Type the scan id (or last 8 chars) to confirm.",
    ),
) -> None:
    """Soft-delete a report into vault/.trash/ (never hard-deletes)."""
    console = Console()
    store = VaultStore()
    try:
        entry = store.get_entry(scan_id)
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    short = entry.scan_id[-8:]
    token = confirm
    if token is None and not yes:
        token = typer.prompt(f"Type {short} to soft-delete this report")
    if yes and token is None:
        token = short
    assert token is not None
    try:
        dest = store.soft_delete(entry.scan_id, confirm_id=token)
    except VaultSafetyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"Moved to trash: {dest}")


@vault_app.command("diff")
def vault_diff(
    scan_a: str = typer.Argument(..., help="Baseline / older scan id."),
    scan_b: str = typer.Argument(..., help="Newer scan id."),
) -> None:
    """Diff two scans by stable finding id."""
    console = Console()
    store = VaultStore()
    try:
        a = store.load_scan(scan_a)
        b = store.load_scan(scan_b)
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    result = diff_scans(a, b)
    console.print(
        f"Diff {result.a_id[-10:]} → {result.b_id[-10:]} on {result.host}: "
        f"new={result.new_count} resolved={result.resolved_count} "
        f"changed={result.changed_count}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Kind")
    table.add_column("Title")
    table.add_column("Detail")
    for item in result.items:
        if item.kind == DiffKind.UNCHANGED:
            continue
        finding = item.after or item.before
        title = finding.title if finding else item.finding_id
        detail = ", ".join(item.changes) if item.changes else ""
        table.add_row(item.kind.value, title[:70], detail)
    console.print(table)
