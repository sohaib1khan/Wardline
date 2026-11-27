"""Live scan view — plugin rows, progress animation, streaming findings."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, ProgressBar, RichLog, Static

from wardline.backends.local import LocalBackend
from wardline.core.config import load_config
from wardline.core.engine import run_scan
from wardline.core.events import Event, EventBus, EventKind
from wardline.core.profiles import resolve_plugin_names
from wardline.tui.screens.dashboard import DashboardScreen
from wardline.tui.widgets.header import WardHeader

_SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_BAR_WIDTH = 28


@dataclass
class PluginRowState:
    name: str
    status: str = "queued"
    findings: int = 0
    detail: str = ""
    duration: str = ""


class LiveScanScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("c", "cancel", "Cancel"),
        ("escape", "back", "Back"),
    ]

    running: reactive[bool] = reactive(True)

    def __init__(
        self,
        *,
        profile: str = "quick",
        plugins: list[str] | None = None,
        plugin_options: dict[str, dict] | None = None,
    ) -> None:
        super().__init__()
        self.profile = profile
        self.plugin_names = resolve_plugin_names(profile=profile, plugins=plugins)
        self.plugin_options = plugin_options
        self._rows: dict[str, PluginRowState] = {
            name: PluginRowState(name=name) for name in self.plugin_names
        }
        self._cancel = asyncio.Event()
        self._worker_task: asyncio.Task[None] | None = None
        self._saved_scan_id: str | None = None
        self._saved_path: str | None = None
        self._spin_idx = 0
        self._started_at = time.monotonic()
        self._done_count = 0
        self._anim_timer = None

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical():
            yield Static(self._header_text(), id="live-header", classes="panel")
            yield Static(self._progress_text(), id="live-progress", classes="panel")
            yield ProgressBar(total=max(1, len(self.plugin_names)), show_eta=False, id="live-bar")
            yield Static(self._render_rows(), id="plugin-rows", classes="panel")
            yield Static("Findings stream", classes="muted")
            yield RichLog(id="findings-stream", markup=True, highlight=False)
            yield Static("", id="live-path", classes="muted")
            yield Button("Cancel", id="btn-cancel")
            yield Button("View findings", id="btn-view", disabled=True)
            yield Button("Open Vault", id="btn-vault", disabled=True)
        yield Footer()

    def _header_text(self) -> str:
        return f"WARDLINE  ·  {self.profile}  ·  local  ·  live scan"

    def _progress_text(self) -> str:
        total = max(1, len(self.plugin_names))
        done = self._done_count
        pct = int(done / total * 100)
        elapsed = time.monotonic() - self._started_at
        spin = _SPINNER[self._spin_idx % len(_SPINNER)] if self.running else "✓"
        filled = round(done / total * _BAR_WIDTH)
        bar = "█" * filled + "░" * (_BAR_WIDTH - filled)
        phase = "scanning" if self.running else "complete"
        current = next(
            (n for n, r in self._rows.items() if r.status == "running"),
            "—",
        )
        return (
            f"{spin}  {phase:<9}  [{bar}]  {pct:3d}%  "
            f"{done}/{total} plugins  ·  {elapsed:5.1f}s  ·  current {current}"
        )

    def _render_rows(self) -> str:
        lines: list[str] = []
        spin = _SPINNER[self._spin_idx % len(_SPINNER)]
        for name, row in self._rows.items():
            if row.status == "running":
                glyph = spin
            else:
                glyph = {
                    "queued": "·",
                    "ok": "✓",
                    "findings": "✓",
                    "skipped": "-",
                    "unavailable": "-",
                    "failed": "✗",
                    "timed_out": "✗",
                }.get(row.status, "·")
            dur = f"{row.duration:>6}" if row.duration else "      "
            find = f"{row.findings} finding(s)" if row.findings else ""
            detail = row.detail or find
            lines.append(f"{glyph} {name:<16} {dur}  {row.status:<12} {detail}")
        return "\n".join(lines) if lines else "(no plugins)"

    def on_mount(self) -> None:
        bar = self.query_one("#live-bar", ProgressBar)
        bar.update(total=max(1, len(self.plugin_names)), progress=0)
        reduce_motion = getattr(self.app, "reduce_motion", False)
        if not reduce_motion:
            self._anim_timer = self.set_interval(0.08, self._tick_animation)
        self._worker_task = asyncio.create_task(self._run())

    def _tick_animation(self) -> None:
        if not self.running:
            return
        self._spin_idx += 1
        self._refresh_progress()
        self._refresh_rows()

    def _refresh_progress(self) -> None:
        self.query_one("#live-progress", Static).update(self._progress_text())
        bar = self.query_one("#live-bar", ProgressBar)
        bar.update(progress=self._done_count)

    async def _run(self) -> None:
        bus = EventBus()
        queue = bus.subscribe()
        consumer = asyncio.create_task(self._consume(queue))
        backend = LocalBackend()
        cfg = getattr(self.app, "ward_config", None) or load_config()
        try:
            for name in self._rows:
                self._rows[name].status = "queued"
            self._refresh_rows()
            self._refresh_progress()

            if self._cancel.is_set():
                return

            outcome = await run_scan(
                backend,
                profile=self.profile,
                plugin_names=self.plugin_names,
                config=cfg,
                bus=bus,
                plugin_options=self.plugin_options,
            )
            vault = self.app.vault  # type: ignore[attr-defined]
            previous = vault.recent_for_host(outcome.scan.host.hostname, limit=5)
            path = vault.save(
                outcome.scan,
                raw_by_plugin=outcome.raw_by_plugin,
                previous_scans=previous,
            )
            self._saved_scan_id = outcome.scan.id
            self._saved_path = str(path)
            self.notify(
                f"Scan saved · posture {outcome.scan.scores.posture} · {path.name}",
                title="Vault",
                severity="information",
                timeout=6,
            )
            log = self.query_one("#findings-stream", RichLog)
            log.write(
                f"[bold green]done[/] posture={outcome.scan.scores.posture} "
                f"findings={outcome.scan.summary.total_findings} id=…{outcome.scan.id[-8:]}"
            )
            log.write(f"[dim]stored at[/] {path}")
            self.query_one("#live-path", Static).update(
                f"Saved → {path}\n"
                f"Reports: {path / 'report.html'} · {path / 'report.md'} · {path / 'scan.json'}"
            )
            self.query_one("#btn-view", Button).disabled = False
            self.query_one("#btn-vault", Button).disabled = False
        except asyncio.CancelledError:
            log = self.query_one("#findings-stream", RichLog)
            log.write("[yellow]scan cancelled[/]")
            raise
        except Exception as exc:
            self.notify(f"Scan failed: {exc}", severity="error")
            self.query_one("#findings-stream", RichLog).write(f"[red]error[/] {exc}")
        finally:
            await bus.close()
            await consumer
            self.running = False
            if self._anim_timer is not None:
                self._anim_timer.stop()
                self._anim_timer = None
            self._done_count = len(self.plugin_names)
            self._refresh_progress()
            self._refresh_rows()
            cancel_btn = self.query_one("#btn-cancel", Button)
            cancel_btn.label = "Back to dashboard"

    async def _consume(self, queue: asyncio.Queue) -> None:
        log = self.query_one("#findings-stream", RichLog)
        while True:
            item = await queue.get()
            if item is None:
                break
            assert isinstance(item, Event)
            if item.kind == EventKind.PLUGIN_STARTED and item.plugin:
                row = self._rows.get(item.plugin)
                if row:
                    row.status = "running"
                    row.detail = "running…"
                    self._refresh_rows()
                    self._refresh_progress()
            elif item.kind == EventKind.PLUGIN_FINISHED and item.plugin:
                row = self._rows.get(item.plugin)
                if row:
                    row.status = str(item.data.get("status") or item.message or "ok")
                    row.findings = int(item.data.get("findings") or 0)
                    dur = item.data.get("duration_seconds")
                    if isinstance(dur, (int, float)):
                        row.duration = f"{dur:.1f}s"
                    skip = item.data.get("skip_reason")
                    if skip:
                        row.detail = str(skip)
                    self._done_count = sum(
                        1
                        for r in self._rows.values()
                        if r.status not in {"queued", "running"}
                    )
                    self._refresh_rows()
                    self._refresh_progress()
            elif item.kind == EventKind.PLUGIN_SKIPPED and item.plugin:
                row = self._rows.get(item.plugin)
                if row:
                    row.status = str(item.data.get("status") or "skipped")
                    row.detail = item.message
                    self._done_count = sum(
                        1
                        for r in self._rows.values()
                        if r.status not in {"queued", "running"}
                    )
                    self._refresh_rows()
                    self._refresh_progress()
            elif item.kind == EventKind.FINDING:
                sev = str(item.data.get("severity") or "info")
                color = {
                    "critical": "red",
                    "high": "dark_orange",
                    "medium": "yellow",
                    "low": "white",
                    "info": "cyan",
                }.get(sev, "white")
                log.write(f"[{color}]{sev.upper():<8}[/{color}] {item.plugin}: {item.message}")
                if item.plugin and item.plugin in self._rows:
                    self._rows[item.plugin].findings += 1
                    self._refresh_rows()

    def _refresh_rows(self) -> None:
        self.query_one("#plugin-rows", Static).update(self._render_rows())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.action_cancel()
        elif event.button.id == "btn-view":
            self.action_view_findings()
        elif event.button.id == "btn-vault":
            self.action_open_vault()

    def action_cancel(self) -> None:
        if not self.running:
            self.action_back()
            return
        self._cancel.set()
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
        self.notify("Cancelling scan…", severity="warning")

    def action_view_findings(self) -> None:
        if not self._saved_scan_id:
            self.notify("No saved scan yet", severity="warning")
            return
        from wardline.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(scan_id=self._saved_scan_id))

    def action_open_vault(self) -> None:
        from wardline.tui.screens.vault_browser import VaultScreen

        self.app.push_screen(VaultScreen())

    def action_back(self) -> None:
        self.app.switch_screen(DashboardScreen())
