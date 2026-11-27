"""Scan launcher — pick profile / network targets and start a live scan."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
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

from wardline.backends.local import LocalBackend, read_total_ram_mb
from wardline.core.models import BackendKind
from wardline.core.profiles import PROFILES
from wardline.plugins.base import get_registry
from wardline.tui.widgets.header import WardHeader


class LauncherScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("enter", "start", "Start"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._profile = "quick"

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="launcher-body"):
            yield Static("Scan launcher", id="brand")
            yield Label("Backend: local", classes="muted")
            yield Label("Profile", classes="muted")
            with RadioSet(id="profile-set"):
                for name, profile in PROFILES.items():
                    yield RadioButton(
                        f"{name} — {profile.description}",
                        value=(name == "quick"),
                        id=f"profile-{name}",
                    )
            yield Label("Nmap targets (comma-separated; must be allowlisted or confirmed)", classes="muted")
            yield Input(placeholder="127.0.0.1", id="nmap-targets")
            yield Checkbox(
                "I own / have written permission to scan any target outside the allowlist",
                id="nmap-confirm",
            )
            yield Static("", id="capability", classes="panel")
            yield Static("", id="warnings", classes="panel")
            yield Button("Start scan", variant="primary", id="btn-start", classes="-primary")
            yield Button("Cancel", id="btn-cancel")
        yield Footer()

    def on_mount(self) -> None:
        cfg = getattr(self.app, "ward_config", None)
        if cfg is not None:
            self.query_one("#nmap-targets", Input).value = ", ".join(cfg.scan.nmap.allowed_targets)
        self._refresh_panels("quick")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        pressed = event.pressed
        if pressed is None or not pressed.id:
            return
        if pressed.id.startswith("profile-"):
            name = pressed.id.removeprefix("profile-")
            self._profile = name
            self._refresh_panels(name)

    def _refresh_panels(self, profile_name: str) -> None:
        profile = PROFILES.get(profile_name)
        registry = get_registry()
        lines = [f"Capability matrix (local) for profile '{profile_name}':"]
        names = list(profile.plugins) if profile else []
        for name in names:
            if name not in registry:
                lines.append(f"  · {name}: not registered yet")
                continue
            plugin = registry.get(name)
            cap = plugin.capabilities.get(BackendKind.LOCAL)
            level = cap.level.value if cap else "?"
            note = f" — {cap.note}" if cap and cap.note else ""
            root = " (needs root)" if plugin.needs_root else ""
            lines.append(f"  · {plugin.display_name}: {level}{root}{note}")
        self.query_one("#capability", Static).update("\n".join(lines))

        warnings: list[str] = []
        ram = read_total_ram_mb()
        if "clamav" in names and ram is not None and ram < 4096:
            warnings.append(
                f"ClamAV typically wants ≥4096 MiB RAM (host has {ram} MiB) — confirm before deep scans."
            )
        if "nmap" in names:
            warnings.append(
                "Nmap only scans allowlisted targets (Settings) unless you tick the ownership checkbox."
            )
        backend = LocalBackend()
        if (
            any(registry.get(n).needs_root for n in names if n in registry)
            and not backend.is_root()
        ):
            warnings.append(
                "Some plugins need root — they will be skipped unless re-run with sudo."
            )
        self.query_one("#warnings", Static).update(
            "Warnings:\n" + ("\n".join(f"  ! {w}" for w in warnings) if warnings else "  (none)")
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.action_start()
        elif event.button.id == "btn-cancel":
            self.app.pop_screen()

    def action_start(self) -> None:
        profile = PROFILES.get(self._profile)
        plugins = list(profile.plugins) if profile else None
        registry = get_registry()
        if plugins:
            plugins = [p for p in plugins if p in registry]

        plugin_options: dict[str, dict] = {}
        if plugins and "nmap" in plugins:
            targets = [
                t.strip()
                for t in self.query_one("#nmap-targets", Input).value.split(",")
                if t.strip()
            ]
            cfg = getattr(self.app, "ward_config", None)
            allowed = list(cfg.scan.nmap.allowed_targets) if cfg is not None else ["127.0.0.1"]
            confirm = self.query_one("#nmap-confirm", Checkbox).value
            confirmed = [t for t in targets if t not in set(allowed) and t != "127.0.0.1"]
            if confirmed and not confirm:
                self.app.notify(  # type: ignore[attr-defined]
                    "Out-of-allowlist targets need the ownership checkbox",
                    title="Nmap",
                    severity="error",
                )
                return
            plugin_options["nmap"] = {
                "allowed_targets": allowed,
                "targets": targets or list(allowed),
                "confirmed_targets": confirmed if confirm else [],
            }

        self.app.open_live_scan(  # type: ignore[attr-defined]
            profile=self._profile,
            plugins=plugins or None,
            plugin_options=plugin_options or None,
        )
