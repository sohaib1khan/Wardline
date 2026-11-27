"""Diff view for two Vault scans."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static

from wardline.tui.widgets.header import WardHeader
from wardline.vault.diff import DiffKind, diff_scans
from wardline.vault.store import VaultStore


class DiffScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, scan_a: str, scan_b: str) -> None:
        super().__init__()
        self._a = scan_a
        self._b = scan_b

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="diff-body"):
            yield Static("Vault Diff", id="brand")
            yield Static("", id="diff-summary", classes="panel")
            yield DataTable(id="diff-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#diff-table", DataTable)
        table.add_columns("Kind", "Severity", "Title", "Changes")
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        try:
            a = vault.load_scan(self._a)
            b = vault.load_scan(self._b)
        except (LookupError, OSError, ValueError) as exc:
            self.query_one("#diff-summary", Static).update(f"Cannot load scans: {exc}")
            return
        result = diff_scans(a, b)
        self.query_one("#diff-summary", Static).update(
            f"{a.host.hostname}: {a.id[-10:]} → {b.id[-10:]}  ·  "
            f"new={result.new_count} resolved={result.resolved_count} "
            f"changed={result.changed_count}"
        )
        for item in result.items:
            if item.kind == DiffKind.UNCHANGED:
                continue
            finding = item.after or item.before
            assert finding is not None
            table.add_row(
                item.kind.value,
                finding.severity.value,
                finding.title[:50],
                ", ".join(item.changes) if item.changes else "—",
            )
