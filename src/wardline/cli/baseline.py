"""``wardline baseline`` — Guarded Baseline CLI."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wardline.backends.local import LocalBackend
from wardline.core.baseline import BaselineTool, plan_guarded_baseline, run_guarded_baseline

baseline_app = typer.Typer(
    name="baseline",
    help="Guarded Baseline: verify packages before AIDE init / rkhunter --propupd.",
    no_args_is_help=True,
)


def _run_tool(
    tool: BaselineTool,
    *,
    yes: bool,
    paths: str | None,
    debian_aideinit: bool = False,
) -> int:
    console = Console()
    changed = [p.strip() for p in (paths or "").split(",") if p.strip()]
    backend = LocalBackend()

    async def _go() -> int:
        if not yes:
            plan = await plan_guarded_baseline(
                backend,
                tool,
                changed_paths=changed or None,
                debian_aideinit=debian_aideinit,
            )
            _print_plan(console, plan)
            if plan.blocked:
                if plan.critical_finding:
                    console.print(
                        Panel(
                            f"[bold red]{plan.critical_finding.title}[/bold red]\n"
                            f"{plan.critical_finding.description}",
                            title="Blocked",
                            border_style="red",
                        )
                    )
                return 1
            console.print(
                "[yellow]Dry-run.[/yellow] Re-run with [bold]--yes[/bold] to execute "
                "after reviewing the commands above."
            )
            return 0

        result = await run_guarded_baseline(
            backend,
            tool,
            yes=True,
            changed_paths=changed or None,
            debian_aideinit=debian_aideinit,
        )
        _print_plan(console, result.plan)
        if result.plan.blocked:
            if result.plan.critical_finding:
                console.print(
                    Panel(
                        f"[bold red]{result.plan.critical_finding.title}[/bold red]\n"
                        f"{result.plan.critical_finding.description}",
                        title="Blocked",
                        border_style="red",
                    )
                )
            return 1
        style = "green" if result.executed else "yellow"
        console.print(f"[{style}]{result.message}[/{style}]")
        for cmd_result in result.command_results:
            console.print(
                f"  exit={cmd_result.exit_code}  {' '.join(cmd_result.argv)}"
            )
        return 0 if result.executed else 1

    return asyncio.run(_go())


def _print_plan(console: Console, plan: object) -> None:
    from wardline.core.baseline import BaselinePlan

    assert isinstance(plan, BaselinePlan)
    table = Table(title=f"Guarded Baseline — {plan.tool}", show_header=True)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Changed paths", ", ".join(plan.changed_paths) or "(full verify)")
    table.add_row("Dirty paths", ", ".join(plan.dirty_paths) or "(none)")
    table.add_row("Blocked", "yes" if plan.blocked else "no")
    if plan.block_reason:
        table.add_row("Reason", plan.block_reason)
    table.add_row(
        "Commands",
        "\n".join(" ".join(c) for c in plan.commands) or "(none)",
    )
    console.print(table)
    for note in plan.notes:
        console.print(f"[dim]• {note}[/dim]")


@baseline_app.command("aide")
def baseline_aide(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Execute after a clean package verification (required to mutate).",
    ),
    paths: str | None = typer.Option(
        None,
        "--paths",
        help="Comma-separated paths that changed (verified before init).",
    ),
    debian_aideinit: bool = typer.Option(
        False,
        "--debian-aideinit",
        help="Use `aideinit -y -f` instead of `aide --init`.",
    ),
) -> None:
    """Initialize/refresh the AIDE database after a clean pkg_verify."""
    code = _run_tool(
        "aide",
        yes=yes,
        paths=paths,
        debian_aideinit=debian_aideinit,
    )
    raise typer.Exit(code=code)


@baseline_app.command("rkhunter")
def baseline_rkhunter(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Execute after a clean package verification (required to mutate).",
    ),
    paths: str | None = typer.Option(
        None,
        "--paths",
        help="Comma-separated paths that changed (verified before --propupd).",
    ),
) -> None:
    """Run rkhunter --propupd after a clean pkg_verify."""
    code = _run_tool("rkhunter", yes=yes, paths=paths)
    raise typer.Exit(code=code)
