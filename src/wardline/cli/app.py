"""Top-level Typer application for Wardline."""

from __future__ import annotations

import typer

from wardline import __version__
from wardline.cli.baseline import baseline_app
from wardline.cli.docker_cmd import docker_app
from wardline.cli.doctor import run_doctor
from wardline.cli.guide import run_guide
from wardline.cli.hosts_cmd import hosts_app
from wardline.cli.init_cmd import run_init
from wardline.cli.ports_cmd import ports_app
from wardline.cli.scan import run_scan_command
from wardline.cli.tools_cmd import tools_app
from wardline.cli.vault_cmd import vault_app
from wardline.meta import DOCS_URL, REPO_GIT, REPO_URL

_EPILOG = f"""
[bold]App[/]  {REPO_URL}
[bold]Install[/]  curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash
[bold]Or[/]  uv tool install git+{REPO_GIT}
[bold]Help[/]  wardline guide
[bold]Docker[/]  wardline docker build && wardline docker up
[bold]Docs[/]  {DOCS_URL}

Run with no subcommand to launch the TUI.
"""

app = typer.Typer(
    name="wardline",
    help=(
        "Wardline — all-in-one Linux security scanning TUI and CLI. "
        f"Repo: {REPO_URL}"
    ),
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=True,
    rich_markup_mode="rich",
    epilog=_EPILOG,
)
app.add_typer(vault_app, name="vault")
app.add_typer(baseline_app, name="baseline")
app.add_typer(docker_app, name="docker")
app.add_typer(hosts_app, name="hosts")
app.add_typer(tools_app, name="tools")
app.add_typer(ports_app, name="ports")


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"wardline {__version__}")
        typer.echo(REPO_URL)
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Wardline — unify Linux security scanners into one Finding format and Vault.

    Quick start: wardline guide · wardline init · wardline doctor · wardline
    """
    if ctx.invoked_subcommand is None:
        from wardline.tui.app import run_tui

        run_tui()


@app.command("guide")
def guide_cmd() -> None:
    """Print setup, install, and usage help (recommended first read)."""
    code = run_guide()
    raise typer.Exit(code=code)


@app.command()
def doctor() -> None:
    """Detect distro, backend readiness, tools, and resources."""
    code = run_doctor()
    raise typer.Exit(code=code)


@app.command("init")
def init_cmd(
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite config.toml / hosts.toml with defaults.",
    ),
) -> None:
    """Create config + data directories (first-time install)."""
    code = run_init(force=force)
    raise typer.Exit(code=code)


@app.command()
def scan(
    profile: str = typer.Option(
        "quick",
        "--profile",
        "-p",
        help="Scan profile (quick, standard, deep, network, compliance, incident).",
    ),
    plugins: str | None = typer.Option(
        None,
        "--plugins",
        help="Comma-separated plugin names (overrides profile).",
    ),
    backend: str = typer.Option(
        "local",
        "--backend",
        "-b",
        help="Execution backend (local, docker, or ssh).",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        "-H",
        help="Remote host name from hosts.toml (required for --backend ssh).",
    ),
    all_hosts: bool = typer.Option(
        False,
        "--all-hosts",
        help="Fleet-scan every host in hosts.toml (SSH, concurrency-limited).",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 if findings at or above this severity exist.",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON for the Scan object.",
    ),
    no_save: bool = typer.Option(
        False,
        "--no-save",
        help="Do not write this scan into the Vault.",
    ),
) -> None:
    """Run scanners, print a summary, and auto-save to the Vault."""
    code = run_scan_command(
        profile=profile,
        plugins=plugins,
        backend_name=backend,
        host=host,
        all_hosts=all_hosts,
        fail_on=fail_on,
        as_json=as_json,
        no_save=no_save,
    )
    raise typer.Exit(code=code)


@app.command()
def tui() -> None:
    """Launch the interactive TUI (same as bare `wardline`)."""
    from wardline.tui.app import run_tui

    run_tui()
