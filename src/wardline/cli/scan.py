"""``wardline scan`` — run plugins and print a summary."""

from __future__ import annotations

import asyncio
import json

from rich.console import Console
from rich.table import Table

from wardline.backends.base import BackendError
from wardline.backends.factory import get_backend
from wardline.backends.ssh import SSHBackend
from wardline.core.config import load_config
from wardline.core.engine import fail_on_triggered, run_scan
from wardline.core.fleet import run_fleet_scan
from wardline.core.hosts import load_hosts
from wardline.core.models import Scan, Severity
from wardline.core.profiles import PROFILES
from wardline.vault.store import VaultStore


def run_scan_command(
    *,
    profile: str = "quick",
    plugins: str | None = None,
    backend_name: str = "local",
    host: str | None = None,
    all_hosts: bool = False,
    fail_on: str | None = None,
    as_json: bool = False,
    no_save: bool = False,
    console: Console | None = None,
) -> int:
    """Execute a scan and print results. Returns process exit code."""
    console = console or Console()
    return asyncio.run(
        _scan_async(
            profile=profile,
            plugins=plugins,
            backend_name=backend_name,
            host=host,
            all_hosts=all_hosts,
            fail_on=fail_on,
            as_json=as_json,
            no_save=no_save,
            console=console,
        )
    )


async def _scan_async(
    *,
    profile: str,
    plugins: str | None,
    backend_name: str,
    host: str | None,
    all_hosts: bool,
    fail_on: str | None,
    as_json: bool,
    no_save: bool,
    console: Console,
) -> int:
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None
    if profile not in PROFILES and plugin_list is None:
        console.print(
            f"[red]unknown profile {profile!r}.[/red] Known: {', '.join(sorted(PROFILES))}"
        )
        return 2

    fail_sev: Severity | None = None
    if fail_on:
        try:
            fail_sev = Severity(fail_on.lower())
        except ValueError:
            console.print(
                f"[red]invalid --fail-on {fail_on!r}.[/red] "
                f"Use: {', '.join(s.value for s in Severity)}"
            )
            return 2

    cfg = load_config()
    label = ",".join(plugin_list) if plugin_list else profile

    # Fleet mode
    if all_hosts or (backend_name == "ssh" and host and "," in host):
        names = None if all_hosts else [n.strip() for n in (host or "").split(",") if n.strip()]
        inventory = load_hosts()
        if not inventory.hosts:
            console.print("[red]No hosts in inventory. Use `wardline hosts add`.[/red]")
            return 2
        if not as_json:
            console.print(
                f"[bold]Wardline fleet scan[/bold]  ·  {label}  ·  "
                f"concurrency={inventory.fleet_concurrency}"
            )
        fleet = await run_fleet_scan(
            inventory,
            profile=profile,
            plugin_names=plugin_list,
            host_names=names,
            config=cfg,
            save=not no_save,
        )
        worst = 0
        for item in fleet.results:
            if item.ok and item.outcome:
                if as_json:
                    console.print_json(
                        json.dumps(item.outcome.scan.model_dump(mode="json"), indent=2)
                    )
                else:
                    _print_summary(console, item.outcome.scan)
                if fail_on_triggered(item.outcome.scan, fail_sev):
                    worst = 1
            else:
                console.print(f"[red]{item.host_name}:[/red] {item.error}")
                worst = max(worst, 2 if not item.ok else worst)
        if not as_json:
            console.print(
                f"Fleet: ok={fleet.ok_count} failed={fleet.fail_count}"
            )
        return worst

    try:
        backend = get_backend(backend_name, host=host)
    except BackendError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    if not as_json:
        console.print(f"[bold]Wardline scan[/bold]  ·  {label}  ·  {backend.kind.value}")

    try:
        try:
            outcome = await run_scan(
                backend,
                profile=profile,
                plugin_names=plugin_list,
                config=cfg,
            )
        except Exception as exc:
            console.print(f"[red]scan failed:[/red] {exc}")
            return 2
    finally:
        if isinstance(backend, SSHBackend):
            await backend.close()

    scan = outcome.scan
    saved_path = None
    if cfg.vault.auto_save and not no_save:
        store = VaultStore()
        previous = store.recent_for_host(scan.host.hostname, limit=5)
        saved_path = store.save(
            scan,
            raw_by_plugin=outcome.raw_by_plugin,
            previous_scans=previous,
        )
        if cfg.vault.keep_last_n > 0:
            store.apply_retention(keep_last_n=cfg.vault.keep_last_n)

    if as_json:
        console.print_json(json.dumps(scan.model_dump(mode="json"), indent=2))
    else:
        _print_summary(console, scan)
        if saved_path is not None:
            console.print(f"[dim]Saved to Vault:[/dim] {saved_path}")

    if fail_on_triggered(scan, fail_sev):
        return 1
    return 0


def _print_summary(console: Console, scan: Scan) -> None:
    console.print()
    console.print(
        f"Scan [cyan]{scan.id}[/cyan]  host=[green]{scan.host.hostname}[/green]  "
        f"profile={scan.profile}  posture=[bold]{scan.scores.posture}[/bold]"
        + (
            f"  lynis={scan.scores.lynis_hardening_index}"
            if scan.scores.lynis_hardening_index is not None
            else ""
        )
    )

    plugins = Table(title="Plugins", show_header=True, header_style="bold")
    plugins.add_column("Plugin")
    plugins.add_column("Status")
    plugins.add_column("Duration")
    plugins.add_column("Findings")
    plugins.add_column("Notes")
    finding_counts: dict[str, int] = {}
    for finding in scan.findings:
        finding_counts[finding.plugin] = finding_counts.get(finding.plugin, 0) + 1
    for pr in scan.plugin_results:
        dur = f"{pr.duration_seconds:.1f}s" if pr.duration_seconds is not None else "—"
        notes = pr.skip_reason or ""
        plugins.add_row(
            pr.plugin,
            pr.status.value,
            dur,
            str(finding_counts.get(pr.plugin, 0)),
            notes,
        )
    console.print(plugins)

    sev = scan.summary.by_severity
    console.print(
        f"Findings: critical={sev.critical} high={sev.high} "
        f"medium={sev.medium} low={sev.low} info={sev.info} "
        f"(fp excluded={scan.summary.likely_false_positives})"
    )

    if scan.findings:
        top = Table(title="Top findings", show_header=True, header_style="bold")
        top.add_column("Sev")
        top.add_column("Plugin")
        top.add_column("Title")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(scan.findings, key=lambda f: order.get(f.severity.value, 9))
        for finding in ranked[:15]:
            top.add_row(finding.severity.value, finding.plugin, finding.title[:80])
        console.print(top)
    console.print()
