"""In-app how-to / help for Wardline."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

from wardline.core.paths import describe_storage_layout
from wardline.meta import REPO_GIT, REPO_URL

HELP_MARKDOWN = f"""\
[bold cyan]How to use Wardline[/]

[bold]App[/]  [link={REPO_URL}]{REPO_URL}[/link]

Wardline is a local-first Linux security posture scanner. It runs tools on a
host (local, Docker, or SSH), correlates findings, and stores vault / evidence.

[bold]1. Install (get the [yellow]wardline[/] command)[/]
  • Any distro (Debian / RHEL / Arch):
      [bold]curl -fsSL https://raw.githubusercontent.com/sohaib1khan/Wardline/main/scripts/install.sh | bash[/]
  • System-wide (/usr/local/bin): add [bold]| bash -s -- --system[/]
  • Or: [bold]uv tool install git+{REPO_GIT}[/]
  • Then: [bold]wardline guide[/] · [bold]wardline init[/] · [bold]wardline doctor[/]
  • Scanners: [bold]wardline tools install[/]
  • Docker sidecar: [bold]wardline docker build && wardline docker up[/]
      then [bold]wardline scan --backend docker[/]

[bold]2. Run a scan[/]
  • Dashboard → [bold]Quick scan[/] (key [yellow]r[/])
  • Dashboard → [bold]Network scan[/] (key [yellow]n[/]) — ss + SSH posture + Nmap
  • Dashboard → [bold]Scan launcher[/] (key [yellow]l[/])
  • CLI: [bold]wardline scan --profile network[/]

[bold]3. View results (live + saved)[/]
  • After a live scan: [bold]View findings[/] / [bold]Open Vault[/]
  • [bold]Findings[/] (key [yellow]f[/]) — pick any saved scan
  • [bold]Vault[/] (key [yellow]v[/]) — all saved scans; [yellow]i[/] shows report paths
  • Each scan folder: [bold]scan.json[/], [bold]report.md[/], [bold]report.html[/], [bold]raw/[/]

[bold]4. Settings (must Save)[/]
  • [bold]Settings[/] (key [yellow]s[/]) — theme, evidence, Nmap allowlist, listeners
  • Theme + checkboxes auto-save; press [bold]Save all[/] for scan fields
  • File: ~/.config/wardline/config.toml

[bold]5. Expected ports (CRUD)[/]
  • TUI [bold]Ports[/] (key [yellow]p[/]) · CLI [bold]wardline ports …[/]

[bold]6. Fleet & evidence[/]
  • [bold]Hosts[/] (key [yellow]h[/]) · [bold]Evidence[/] (key [yellow]e[/])

[bold]Keyboard map[/]
  [yellow]k[/] Keys rail (click the ⌨ chip · auto-hides)   [yellow]Ctrl+P[/] Palette
  [yellow]q[/] Quit   [yellow]d[/] Dashboard   [yellow]r[/] Quick   [yellow]n[/] Network   [yellow]l[/] Launcher
  [yellow]h[/] Hosts  [yellow]p[/] Ports   [yellow]f[/] Findings   [yellow]v[/] Vault   [yellow]e[/] Evidence
  [yellow]s[/] Settings  [yellow]?[/] Help
"""


class HelpScreen(Screen[None]):
    """How-to and keyboard reference."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("q", "app.pop_screen", "Back", show=False),
        Binding("d", "go_dashboard", "Dashboard", show=True),
        Binding("question_mark", "app.pop_screen", "Close", show=False),
    ]

    def action_go_dashboard(self) -> None:
        from wardline.tui.screens.dashboard import DashboardScreen

        self.app.switch_screen(DashboardScreen())

    def compose(self) -> ComposeResult:
        storage = describe_storage_layout()
        body = HELP_MARKDOWN + f"\n[bold]Where files are stored[/]\n{storage}\n"
        with Vertical(id="help-root"):
            yield Static("[bold]Help · How to use Wardline[/]", id="help-title")
            with VerticalScroll(id="help-body"):
                yield Static(body, id="help-text", markup=True)
        yield Footer()
