"""Branded Wardline header — animated icon opens the command palette."""

from __future__ import annotations

from textual.timer import Timer
from textual.widgets import Header

# Cycle gives the palette button a “scanning / alive” feel (terminal-safe glyphs).
_PULSE = ("⛨", "◉", "◎", "⬡", "◆", "◎")


class WardHeader(Header):
    """Header with a living shield icon (click → command palette)."""

    def __init__(self, *, show_clock: bool = True) -> None:
        super().__init__(show_clock=show_clock, icon=_PULSE[0])
        self._pulse_i = 0
        self._timer: Timer | None = None

    def on_mount(self) -> None:
        icon = self.query_one("HeaderIcon")
        icon.tooltip = "Command palette  ·  Ctrl+P"
        reduce_motion = getattr(self.app, "reduce_motion", False)
        if not reduce_motion:
            self._timer = self.set_interval(0.7, self._pulse_icon)

    def on_unmount(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def _pulse_icon(self) -> None:
        self._pulse_i = (self._pulse_i + 1) % len(_PULSE)
        self.icon = _PULSE[self._pulse_i]
