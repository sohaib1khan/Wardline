"""Wardline Textual application shell."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import ClassVar

from textual.app import App
from textual.binding import Binding, BindingType
from textual.css.query import NoMatches

from wardline.core.config import WardlineConfig, default_config, ensure_user_config, load_config
from wardline.core.paths import vault_root
from wardline.meta import REPO_URL
from wardline.tui.screens.dashboard import DashboardScreen
from wardline.tui.screens.evidence import EvidenceScreen
from wardline.tui.screens.findings import FindingsScreen
from wardline.tui.screens.launcher import LauncherScreen
from wardline.tui.screens.live import LiveScanScreen
from wardline.tui.screens.settings import SettingsScreen
from wardline.tui.screens.splash import SplashScreen
from wardline.tui.screens.vault_browser import VaultScreen
from wardline.tui.widgets.keys_rail import KeysRail
from wardline.vault.store import VaultStore


class WardlineApp(App[None]):
    """Keyboard-driven TUI for scanning and browsing the Vault."""

    TITLE = "WARDLINE"
    SUB_TITLE = REPO_URL
    # Absolute path so tests (cwd/node path) still load the real theme.
    CSS_PATH = str(Path(__file__).with_name("theme.tcss"))
    # Footer stays lean — full cheat-sheet lives in the keys rail (k / click).
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit", show=True),
        Binding("k", "toggle_keys", "Keys", show=True),
        Binding("question_mark", "go_help", "Help", show=True),
        Binding("ctrl+p", "command_palette", "Palette", show=True),
        Binding("d", "go_dashboard", "Dashboard", show=False),
        Binding("l", "go_launcher", "Launch", show=False),
        Binding("f", "go_findings", "Findings", show=False),
        Binding("v", "go_vault", "Vault", show=False),
        Binding("e", "go_evidence", "Evidence", show=False),
        Binding("s", "go_settings", "Settings", show=False),
        Binding("h", "go_hosts", "Hosts", show=False),
        Binding("p", "go_ports", "Ports", show=False),
    ]

    def __init__(
        self,
        *,
        config: WardlineConfig | None = None,
        vault: VaultStore | None = None,
        start: str = "splash",
        auto_advance: bool = True,
        splash_delay: float = 1.2,
        demo_mode: bool = False,
        splash_status: str | None = None,
        findings_scan_id: str | None = None,
    ) -> None:
        super().__init__()
        self.ward_config = config or default_config()
        self.vault = vault or VaultStore()
        self.start_screen = start
        self.auto_advance = auto_advance
        self.splash_delay = splash_delay
        self.demo_mode = demo_mode
        self.splash_status = splash_status
        self.reduce_motion = self.ward_config.ui.reduce_motion
        self.findings_scan_id = findings_scan_id

    def on_mount(self) -> None:
        theme = self.ward_config.ui.theme
        # Textual built-in dark/light; our CSS supplies Wardline colors either way.
        self.theme = "textual-dark" if theme == "dark" else "textual-light"

        if self.start_screen == "splash":
            self.push_screen(
                SplashScreen(
                    auto_advance=self.auto_advance,
                    delay=0.05 if self.reduce_motion else self.splash_delay,
                    status_text=self.splash_status,
                )
            )
        elif self.start_screen == "dashboard":
            self.push_screen(DashboardScreen())
        elif self.start_screen == "launcher":
            self.push_screen(LauncherScreen())
        elif self.start_screen == "live":
            self.push_screen(LiveScanScreen(profile="quick", plugins=["ss_baseline"]))
        elif self.start_screen == "findings":
            self.push_screen(FindingsScreen(scan_id=self.findings_scan_id))
        elif self.start_screen == "vault":
            self.push_screen(VaultScreen())
        elif self.start_screen == "evidence":
            self.push_screen(EvidenceScreen())
        elif self.start_screen == "settings":
            self.push_screen(SettingsScreen())
        elif self.start_screen == "hosts":
            from wardline.tui.screens.hosts import HostsScreen

            self.push_screen(HostsScreen())
        elif self.start_screen == "help":
            from wardline.tui.screens.help import HelpScreen

            self.push_screen(HelpScreen())
        elif self.start_screen == "ports":
            from wardline.tui.screens.ports import PortsScreen

            self.push_screen(PortsScreen())
        else:
            self.push_screen(DashboardScreen())

    def push_screen(self, screen, *args, **kwargs):  # type: ignore[no-untyped-def, override]
        result = super().push_screen(screen, *args, **kwargs)
        self.call_after_refresh(self._attach_keys_rail)
        return result

    def switch_screen(self, screen, *args, **kwargs):  # type: ignore[no-untyped-def, override]
        result = super().switch_screen(screen, *args, **kwargs)
        self.call_after_refresh(self._attach_keys_rail)
        return result

    def _attach_keys_rail(self) -> None:
        """Mount a collapsed keys chip on the active screen (skip splash)."""
        screen = self.screen
        if screen is None or isinstance(screen, SplashScreen):
            return
        # Never let Textual's 33%-width HelpPanel linger.
        screen.query("HelpPanel").remove()
        if screen.query("KeysRail"):
            return
        with contextlib.suppress(Exception):
            screen.mount(KeysRail())

    def _keys_rail(self) -> KeysRail | None:
        try:
            return self.screen.query_one(KeysRail)
        except NoMatches:
            return None

    def action_toggle_keys(self) -> None:
        self._attach_keys_rail()
        rail = self._keys_rail()
        if rail is not None:
            rail.toggle()

    def action_show_help_panel(self) -> None:
        """Command-palette Keys opens our slim rail, not Textual's sidebar."""
        self._attach_keys_rail()
        rail = self._keys_rail()
        if rail is not None:
            rail.expanded = True

    def action_hide_help_panel(self) -> None:
        rail = self._keys_rail()
        if rail is not None:
            rail.collapse()
        self.screen.query("HelpPanel").remove()

    def action_go_dashboard(self) -> None:
        self.action_hide_help_panel()
        self.switch_screen(DashboardScreen())

    def action_go_launcher(self) -> None:
        self.action_hide_help_panel()
        self.push_screen(LauncherScreen())

    def action_go_findings(self) -> None:
        self.action_hide_help_panel()
        self.push_screen(FindingsScreen())

    def action_go_vault(self) -> None:
        self.action_hide_help_panel()
        self.push_screen(VaultScreen())

    def action_go_evidence(self) -> None:
        self.action_hide_help_panel()
        self.push_screen(EvidenceScreen())

    def action_go_settings(self) -> None:
        self.action_hide_help_panel()
        self.push_screen(SettingsScreen())

    def action_go_hosts(self) -> None:
        from wardline.tui.screens.hosts import HostsScreen

        self.action_hide_help_panel()
        self.push_screen(HostsScreen())

    def action_go_help(self) -> None:
        from wardline.tui.screens.help import HelpScreen

        self.action_hide_help_panel()
        self.push_screen(HelpScreen())

    def action_go_ports(self) -> None:
        from wardline.tui.screens.ports import PortsScreen

        self.action_hide_help_panel()
        self.push_screen(PortsScreen())

    def open_live_scan(
        self,
        *,
        profile: str = "quick",
        plugins: list[str] | None = None,
        plugin_options: dict[str, dict] | None = None,
    ) -> None:
        self.action_hide_help_panel()
        self.push_screen(
            LiveScanScreen(
                profile=profile,
                plugins=plugins,
                plugin_options=plugin_options,
            )
        )


def run_tui(
    *,
    config: WardlineConfig | None = None,
    data_dir: Path | None = None,
) -> None:
    """Entry point used by the CLI."""
    if config is None:
        with contextlib.suppress(OSError):
            ensure_user_config()
        cfg = load_config()
    else:
        cfg = config
    vault = VaultStore(vault_root(data_dir) if data_dir is not None else None)
    app = WardlineApp(config=cfg, vault=vault)
    app.run()
