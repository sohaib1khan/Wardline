"""Animated splash + host/tool detection, then auto-continue to dashboard."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Static

from wardline.backends.local import LocalBackend
from wardline.plugins.base import get_registry
from wardline.tui.screens.dashboard import DashboardScreen
from wardline.tui.widgets.logo import TAGLINE, WORDMARK

_BAR_FRAMES = (
    "[                    ]",
    "[=                   ]",
    "[==                  ]",
    "[===                 ]",
    "[====                ]",
    "[ =====              ]",
    "[  ======            ]",
    "[   =======          ]",
    "[    ========        ]",
    "[     =========      ]",
    "[      ==========    ]",
    "[       ===========  ]",
    "[        ============]",
    "[====================]",
)


class SplashScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("enter", "continue", "Continue"),
        ("escape", "continue", "Skip"),
    ]

    def __init__(
        self,
        *,
        auto_advance: bool = True,
        delay: float = 1.2,
        status_text: str | None = None,
    ) -> None:
        super().__init__()
        self.auto_advance = auto_advance
        self.delay = delay
        # When set, skip live detection (used for deterministic snapshots).
        self.status_text = status_text

    def compose(self) -> ComposeResult:
        with Vertical(id="splash"):
            yield Static("", id="splash-logo")
            yield Static(TAGLINE, id="splash-tagline")
            initial = self.status_text or "Detecting host…"
            yield Static(initial, id="splash-status")
            yield Static(_BAR_FRAMES[0], id="splash-bar")
        yield Footer()

    def on_mount(self) -> None:
        if self.status_text is not None:
            self.query_one("#splash-logo", Static).update(WORDMARK)
            if self.auto_advance:
                self.set_timer(0.05, self.action_continue)
            return
        self.run_worker(self._boot(), exclusive=True)

    async def _boot(self) -> None:
        logo = self.query_one("#splash-logo", Static)
        status = self.query_one("#splash-status", Static)
        bar = self.query_one("#splash-bar", Static)
        reduce_motion = getattr(self.app, "reduce_motion", False)

        if reduce_motion:
            logo.update(WORDMARK)
        else:
            await self._reveal_logo(logo)

        backend = LocalBackend()
        line = "Detecting host…"
        status.update(line)
        try:
            info = await backend.host_info()
            root = "root" if info.is_root else "user"
            line = (
                f"{info.hostname} · {info.distro} {info.version} · "
                f"{info.arch} · {root} · {info.ram_mb or '?'} MiB"
            )
        except Exception as exc:
            line = f"detection error: {exc}"
        status.update(line)
        await self._tick_bar(bar, 3, reduce_motion)

        registry = get_registry()
        plugins = registry.list(include_hidden=False)
        ok = 0
        missing = 0
        for plugin in plugins:
            detect = await plugin.detect(backend)
            if detect.installed and not detect.denylisted:
                ok += 1
            else:
                missing += 1
        status.update(
            f"{line}\ntools: {ok} ready · {missing} missing/unavailable · backend local"
        )
        await self._tick_bar(bar, len(_BAR_FRAMES) - 1, reduce_motion)
        bar.update(_BAR_FRAMES[-1])

        if self.auto_advance:
            wait = 0.05 if reduce_motion else max(0.35, self.delay * 0.4)
            if not reduce_motion:
                logo.styles.opacity = 0.7
                await asyncio.sleep(wait / 2)
                logo.styles.opacity = 1.0
                await asyncio.sleep(wait / 2)
            else:
                await asyncio.sleep(wait)
            self.action_continue()

    async def _reveal_logo(self, logo: Static) -> None:
        lines = WORDMARK.splitlines()
        shown: list[str] = []
        for line in lines:
            shown.append(line)
            logo.update("\n".join(shown))
            await asyncio.sleep(0.05)

    async def _tick_bar(self, bar: Static, end_idx: int, reduce_motion: bool) -> None:
        if reduce_motion:
            bar.update(_BAR_FRAMES[min(end_idx, len(_BAR_FRAMES) - 1)])
            return
        for i in range(min(end_idx + 1, len(_BAR_FRAMES))):
            bar.update(_BAR_FRAMES[i])
            await asyncio.sleep(0.028)

    def action_continue(self) -> None:
        self.app.switch_screen(DashboardScreen())
