"""Guarded Baseline dialog — verify packages before AIDE/rkhunter update."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from wardline.backends.local import LocalBackend
from wardline.core.baseline import BaselinePlan, BaselineTool, plan_guarded_baseline


class BaselineDialog(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="baseline-dialog", classes="panel"):
            yield Label("Guarded Baseline")
            yield Label("Package verification runs first. Dirty files block the update.", classes="muted")
            yield Select(
                [("aide", "aide"), ("rkhunter", "rkhunter")],
                value="aide",
                id="bl-tool",
                allow_blank=False,
            )
            yield Input(placeholder="Changed paths (comma-separated, optional)", id="bl-paths")
            yield Static("Press Verify to plan the action.", id="bl-status")
            with Horizontal():
                yield Button("Verify", id="btn-verify", classes="-primary")
                yield Button("Close", id="btn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)
        elif event.button.id == "btn-verify":
            self.run_worker(self._verify(), exclusive=True)

    async def _verify(self) -> None:
        tool = str(self.query_one("#bl-tool", Select).value)
        paths_raw = self.query_one("#bl-paths", Input).value
        paths = [p.strip() for p in paths_raw.split(",") if p.strip()]
        status = self.query_one("#bl-status", Static)
        status.update("Running package verification…")
        backend = LocalBackend()
        plan: BaselinePlan = await plan_guarded_baseline(
            backend,
            tool if tool in {"aide", "rkhunter"} else "aide",  # type: ignore[arg-type]
            changed_paths=paths or None,
        )
        self._render_plan(plan)

    def _render_plan(self, plan: BaselinePlan) -> None:
        cmds = "\n".join(" ".join(c) for c in plan.commands) or "(none)"
        if plan.blocked:
            detail = (
                f"[b red]BLOCKED[/]\n{plan.block_reason}\n"
                f"Dirty: {', '.join(plan.dirty_paths) or '(n/a)'}\n"
                f"Would run:\n{cmds}"
            )
            if plan.critical_finding:
                detail += f"\n\n{plan.critical_finding.title}"
        else:
            detail = (
                f"[b green]Clean[/] — ready for --yes via CLI\n"
                f"Notes: {'; '.join(plan.notes) or '—'}\n"
                f"Commands:\n{cmds}\n\n"
                "TUI never auto-executes baseline updates; use "
                "`wardline baseline <tool> --yes` after review."
            )
        self.query_one("#bl-status", Static).update(detail)


# Satisfy type checkers that BaselineTool is the intended Select domain.
_TOOLS: tuple[BaselineTool, ...] = ("aide", "rkhunter")
