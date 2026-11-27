"""Settings screen — themed panels for appearance, storage, and scan options."""

from __future__ import annotations

from typing import ClassVar, Literal

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Static,
)

from wardline.core.config import ensure_user_config, load_config, save_config
from wardline.core.paths import config_file_path, get_config_dir, get_data_dir
from wardline.core.ports import PortError, parse_listener_list
from wardline.meta import REPO_URL
from wardline.tui.widgets.header import WardHeader


class SettingsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("s", "save", "Save"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._loading = True

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with VerticalScroll(id="settings-body"):
            yield Static("[bold]Settings[/]", id="settings-title")
            yield Static(
                f"Saves to {config_file_path()}\n{REPO_URL}",
                id="settings-subtitle",
            )

            with Vertical(classes="settings-panel", id="panel-appearance"):
                yield Static("Appearance", classes="settings-panel-title")
                yield Label("Theme (saved immediately)")
                with RadioSet(id="set-theme"):
                    yield RadioButton("Dark", id="theme-dark", value=True)
                    yield RadioButton("Light", id="theme-light")
                yield Checkbox(
                    "Reduce motion (disable splash / scan animations)",
                    id="set-reduce",
                )

            with Vertical(classes="settings-panel", id="panel-storage"):
                yield Static("Storage", classes="settings-panel-title")
                yield Static(_storage_markup(), id="set-paths")
                yield Checkbox(
                    "Enable Evidence Locker (copy-only, never moves originals)",
                    id="set-evidence",
                )

            with Vertical(classes="settings-panel", id="panel-scan"):
                yield Static("Scanning", classes="settings-panel-title")
                yield Label("Nmap allowlist (comma-separated IPs/hosts)")
                yield Input(placeholder="127.0.0.1", id="set-nmap")
                yield Label("Expected listeners (or open Ports · key p)")
                yield Input(placeholder="22/tcp, 80/tcp, 443/tcp", id="set-ss")
                yield Label("ClamAV scan paths")
                yield Input(placeholder="/home, /var/www, /tmp", id="set-clamav")
                yield Label("chkrootkit false-positive path substrings")
                yield Input(placeholder="/usr/lib/.../fail2ban/tests/", id="set-fp")

            with Horizontal(id="settings-actions"):
                yield Button("Save all", id="btn-save", classes="-primary")
                yield Button("Ports…", id="btn-ports")
                yield Button("Guarded Baseline…", id="btn-baseline")
            yield Static("", id="settings-status")
        yield Footer()

    def on_mount(self) -> None:
        self._loading = True
        try:
            ensure_user_config()
        except OSError as exc:
            self.query_one("#settings-status", Static).update(
                f"[red]Cannot create config file:[/] {exc}"
            )
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        # Prefer on-disk values when the file exists.
        try:
            disk = load_config(missing_ok=True)
            if config_file_path().exists():
                cfg = disk
                self.app.ward_config = disk  # type: ignore[attr-defined]
        except Exception:
            pass

        dark = self.query_one("#theme-dark", RadioButton)
        light = self.query_one("#theme-light", RadioButton)
        if cfg.ui.theme == "light":
            light.value = True
            dark.value = False
        else:
            dark.value = True
            light.value = False
        self.query_one("#set-reduce", Checkbox).value = cfg.ui.reduce_motion
        self.query_one("#set-evidence", Checkbox).value = cfg.evidence.enabled
        self.query_one("#set-nmap", Input).value = ", ".join(cfg.scan.nmap.allowed_targets)
        self.query_one("#set-ss", Input).value = ", ".join(cfg.scan.ss.expected_listeners)
        self.query_one("#set-clamav", Input).value = ", ".join(cfg.scan.clamav.paths)
        self.query_one("#set-fp", Input).value = ", ".join(cfg.scan.false_positives.chkrootkit)
        self._loading = False
        path = config_file_path()
        status = f"[dim]Config file:[/] {path}"
        if path.exists():
            status += "  [green](on disk)[/]"
        else:
            status += "  [yellow](missing — Save will create it)[/]"
        self.query_one("#settings-status", Static).update(status)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if self._loading or event.radio_set.id != "set-theme":
            return
        theme = self._selected_theme()
        self._apply_theme(theme)
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        cfg.ui.theme = theme
        self._persist(cfg, note=f"Theme → {theme}")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if self._loading:
            return
        if event.checkbox.id not in {"set-reduce", "set-evidence"}:
            return
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        cfg.ui.reduce_motion = self.query_one("#set-reduce", Checkbox).value
        cfg.evidence.enabled = self.query_one("#set-evidence", Checkbox).value
        self.app.reduce_motion = cfg.ui.reduce_motion  # type: ignore[attr-defined]
        label = "Reduce motion" if event.checkbox.id == "set-reduce" else "Evidence Locker"
        self._persist(cfg, note=f"{label} updated")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        elif event.button.id == "btn-ports":
            from wardline.tui.screens.ports import PortsScreen

            self.app.push_screen(PortsScreen())  # type: ignore[attr-defined]
        elif event.button.id == "btn-baseline":
            from wardline.tui.screens.baseline_dialog import BaselineDialog

            self.app.push_screen(BaselineDialog())  # type: ignore[attr-defined]

    def _selected_theme(self) -> Literal["dark", "light"]:
        if self.query_one("#theme-light", RadioButton).value:
            return "light"
        return "dark"

    def _apply_theme(self, theme: Literal["dark", "light"]) -> None:
        self.app.theme = "textual-dark" if theme == "dark" else "textual-light"

    def _collect(self) -> object | None:
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        theme = self._selected_theme()
        cfg.ui.theme = theme
        cfg.ui.reduce_motion = self.query_one("#set-reduce", Checkbox).value
        cfg.evidence.enabled = self.query_one("#set-evidence", Checkbox).value
        cfg.scan.nmap.allowed_targets = _split(self.query_one("#set-nmap", Input).value)
        try:
            cfg.scan.ss.expected_listeners = parse_listener_list(
                self.query_one("#set-ss", Input).value
            )
        except PortError as exc:
            self.app.notify(str(exc), title="Settings", severity="error")  # type: ignore[attr-defined]
            return None
        cfg.scan.clamav.paths = _split(self.query_one("#set-clamav", Input).value)
        cfg.scan.false_positives.chkrootkit = _split(self.query_one("#set-fp", Input).value)
        return cfg

    def _persist(self, cfg: object, *, note: str) -> bool:
        try:
            path = save_config(cfg)  # type: ignore[arg-type]
            reloaded = load_config(path, missing_ok=False)
            self.app.ward_config = reloaded  # type: ignore[attr-defined]
            self.app.reduce_motion = reloaded.ui.reduce_motion  # type: ignore[attr-defined]
            self._apply_theme(reloaded.ui.theme)  # type: ignore[arg-type]
            self.query_one("#settings-status", Static).update(
                f"[green]Saved[/] {path}  ·  theme={reloaded.ui.theme}"
            )
            self.app.notify(f"{note} · {path}", title="Settings")  # type: ignore[attr-defined]
            return True
        except OSError as exc:
            self.query_one("#settings-status", Static).update(
                f"[red]Save failed:[/] {exc}  ·  path {config_file_path()}"
            )
            self.app.notify(  # type: ignore[attr-defined]
                f"Could not write config: {exc}",
                title="Settings",
                severity="error",
            )
            return False

    def action_save(self) -> None:
        cfg = self._collect()
        if cfg is None:
            return
        self.app.reduce_motion = cfg.ui.reduce_motion  # type: ignore[attr-defined]
        self._apply_theme(cfg.ui.theme)  # type: ignore[attr-defined]
        self._persist(cfg, note="Settings saved")


def _storage_markup() -> str:
    cfg = get_config_dir()
    data = get_data_dir()
    rows = [
        ("Config", str(cfg)),
        ("  config.toml", str(cfg / "config.toml")),
        ("  hosts.toml", str(cfg / "hosts.toml")),
        ("Data", str(data)),
        ("  Vault", f"{data / 'vault'}  ·  scan.json · report.md/html · raw/"),
        ("  Evidence", str(data / "evidence")),
        ("  Cache", str(data / "cache")),
        ("  Logs", str(data / "logs" / "wardline.log")),
    ]
    lines = [f"[dim]{label:<14}[/] {path}" for label, path in rows]
    lines.append("")
    lines.append("[dim]Overrides[/]  WARDLINE_CONFIG_DIR · WARDLINE_DATA_DIR")
    lines.append("[dim]Perms[/]      dirs 0700 · files 0600")
    return "\n".join(lines)


def _split(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]
