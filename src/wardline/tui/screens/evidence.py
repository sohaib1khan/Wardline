"""Evidence Locker browser — list copied files (never modifies originals)."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static

from wardline.core.paths import evidence_root
from wardline.tui.widgets.header import WardHeader
from wardline.vault.evidence import EvidenceItem, EvidenceLocker


class EvidenceScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="evidence-body"):
            yield Static("Evidence Locker", id="brand")
            yield Static("", id="evidence-meta", classes="muted")
            yield DataTable(id="evidence-table", cursor_type="row", zebra_stripes=True)
            yield Static("Select an item", id="evidence-detail", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#evidence-table", DataTable)
        table.add_columns("SHA256", "Original", "Size", "Finding", "Copied")
        self.refresh_list()

    def refresh_list(self) -> None:
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        enabled = cfg.evidence.enabled
        root = evidence_root()
        # Prefer locker rooted next to the app vault when tests override vault root.
        vault = self.app.vault  # type: ignore[attr-defined]
        locker_root = vault.root.parent / "evidence"
        locker = EvidenceLocker(locker_root, config=cfg.evidence)
        self._items: list[EvidenceItem] = locker.list_items()
        meta = self.query_one("#evidence-meta", Static)
        # Avoid absolute paths in the UI (keeps snapshots stable).
        meta.update(
            f"{'enabled' if enabled else 'disabled'} · {len(self._items)} item(s)"
            + (" · locker ready" if locker_root.exists() or root.exists() else "")
        )
        table = self.query_one("#evidence-table", DataTable)
        table.clear()
        for item in self._items:
            table.add_row(
                item.sha256[:12],
                item.original_path[-40:],
                str(item.size),
                item.finding_id[:8] or "—",
                item.copied_at[:19].replace("T", " "),
                key=item.sha256,
            )
        if self._items:
            self._show(self._items[0])

    def _show(self, item: EvidenceItem) -> None:
        text = (
            f"SHA256: {item.sha256}\n"
            f"Original: {item.original_path}\n"
            f"Copy: {item.copy_path}\n"
            f"Owner: {item.owner}  mode: {oct(item.mode)}  size: {item.size}\n"
            f"Finding: {item.finding_id}  Scan: {item.scan_id}\n"
            f"Copied: {item.copied_at}"
        )
        self.query_one("#evidence-detail", Static).update(text)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        sha = str(event.row_key.value)
        item = next((i for i in self._items if i.sha256 == sha), None)
        if item:
            self._show(item)
