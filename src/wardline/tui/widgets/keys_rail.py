"""Slim collapsible keys rail — replaces the bulky Textual HelpPanel sidebar."""

from __future__ import annotations

from textual.reactive import reactive
from textual.timer import Timer
from textual.widgets import Static

_COLLAPSED = "[bold $accent]⌨[/]"

_OPEN = """\
[bold $accent]⌨ keys[/]  [dim]k·click[/]
[dim]───────────────[/]
[bold]r[/] Quick      [bold]n[/] Network
[bold]l[/] Launch     [bold]f[/] Findings
[bold]v[/] Vault      [bold]p[/] Ports
[bold]h[/] Hosts      [bold]s[/] Settings
[bold]d[/] Dashboard  [bold]?[/] Help
[bold]e[/] Evidence   [bold]^p[/] Palette
[bold]q[/] Quit
[dim]auto-hides · k[/]
"""

_AUTO_HIDE_SECONDS = 8.0


class KeysRail(Static):
    """Docked right: collapsed chip ↔ compact cheat-sheet."""

    BINDING_GROUP_TITLE = "Keys rail"

    expanded: reactive[bool] = reactive(False)

    DEFAULT_CSS = """
    KeysRail {
        dock: right;
        width: 5;
        height: auto;
        margin: 1 1 3 0;
        padding: 0 1;
        background: $panel;
        border: tall $accent;
        color: $text;
        text-align: center;
    }

    KeysRail.-open {
        width: 22;
        height: auto;
        text-align: left;
        padding: 1;
    }

    KeysRail:hover {
        border: tall $secondary;
        background: $boost;
    }
    """

    def __init__(self) -> None:
        super().__init__(id="keys-rail")
        self._hide_timer: Timer | None = None

    def on_mount(self) -> None:
        self.update(_COLLAPSED)
        self.tooltip = "Keys  ·  press k or click"

    def on_unmount(self) -> None:
        self._cancel_hide()

    def watch_expanded(self, expanded: bool) -> None:
        self.set_class(expanded, "-open")
        self.update(_OPEN if expanded else _COLLAPSED)
        self.tooltip = (
            "Click or press k to collapse" if expanded else "Keys  ·  press k or click"
        )
        self._cancel_hide()
        if expanded:
            self._hide_timer = self.set_timer(_AUTO_HIDE_SECONDS, self.collapse)

    def on_click(self) -> None:
        self.expanded = not self.expanded

    def toggle(self) -> bool:
        self.expanded = not self.expanded
        return self.expanded

    def collapse(self) -> None:
        self.expanded = False

    def _cancel_hide(self) -> None:
        if self._hide_timer is not None:
            self._hide_timer.stop()
            self._hide_timer = None
