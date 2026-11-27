"""Vault browser — list, open findings, tag, typed soft-delete, diff entry."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Input, Label, Static

from wardline.tui.screens.diff_view import DiffScreen
from wardline.tui.screens.findings import FindingsScreen
from wardline.tui.widgets.header import WardHeader
from wardline.vault.safety import VaultSafetyError
from wardline.vault.store import VaultEntry, VaultStore


class ConfirmDeleteScreen(ModalScreen[bool]):
    """Typed confirmation before soft-deleting a Vault report."""

    def __init__(self, scan_id: str) -> None:
        super().__init__()
        self._scan_id = scan_id
        self._short = scan_id[-8:]

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-delete", classes="panel"):
            yield Label(f"Soft-delete scan …{self._short}?")
            yield Label(f"Type the last 8 characters ({self._short}) to confirm:", classes="muted")
            yield Input(placeholder=self._short, id="confirm-input")
            with Horizontal():
                yield Button("Cancel", id="btn-cancel")
                yield Button("Delete", variant="error", id="btn-delete")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-delete":
            typed = self.query_one("#confirm-input", Input).value.strip()
            self.dismiss(typed in {self._scan_id, self._short, self._scan_id[-10:]})


class VaultScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("f", "open_findings", "Findings"),
        ("i", "show_paths", "Paths"),
        ("t", "add_tag", "Tag"),
        ("x", "delete_scan", "Delete"),
        ("c", "diff_selected", "Diff"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[VaultEntry] = []
        self._selected: list[str] = []

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="vault-body"):
            yield Static("Vault — saved scan results", id="brand")
            yield Label(
                "Select a scan · [f] findings · [i] paths · [t] tag · [c] diff two · [x] delete",
                classes="muted",
            )
            yield DataTable(id="vault-table", cursor_type="row", zebra_stripes=True)
            yield Static("Select a scan to see on-disk paths", id="vault-paths", classes="panel")
            yield Input(placeholder="Tag to add to selected scan", id="vault-tag")
            with Horizontal():
                yield Button("Open findings", id="btn-open", classes="-primary")
                yield Button("Show paths", id="btn-paths")
                yield Button("Add tag", id="btn-tag")
                yield Button("Diff two", id="btn-diff")
                yield Button("Soft delete", id="btn-delete")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#vault-table", DataTable)
        table.add_columns("ID", "Host", "When", "Profile", "Posture", "C/H/M", "Tags")
        self.refresh_list()

    def on_screen_resume(self) -> None:
        self.refresh_list()

    def refresh_list(self) -> None:
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        self._entries = vault.list_scans(limit=50)
        table = self.query_one("#vault-table", DataTable)
        table.clear()
        for entry in self._entries:
            table.add_row(
                entry.scan_id[-10:],
                entry.host,
                entry.started_at.replace("T", " ")[:16],
                entry.profile,
                str(entry.posture),
                f"{entry.critical}/{entry.high}/{entry.medium}",
                ",".join(entry.tags) if entry.tags else "",
                key=entry.scan_id,
            )

    def _current_id(self) -> str | None:
        table = self.query_one("#vault-table", DataTable)
        if table.cursor_row is None or table.cursor_row < 0:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        if row_key is None:
            return None
        return str(row_key.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-open":
            self.action_open_findings()
        elif event.button.id == "btn-paths":
            self.action_show_paths()
        elif event.button.id == "btn-tag":
            self.action_add_tag()
        elif event.button.id == "btn-diff":
            self.action_diff_selected()
        elif event.button.id == "btn-delete":
            self.action_delete_scan()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        self._update_paths(str(event.row_key.value))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        sid = str(event.row_key.value)
        if sid in self._selected:
            self._selected.remove(sid)
        else:
            self._selected.append(sid)
            if len(self._selected) > 2:
                self._selected = self._selected[-2:]
        self.app.notify(  # type: ignore[attr-defined]
            f"Diff selection: {len(self._selected)} scan(s)",
            title="Vault",
            timeout=2,
        )

    def action_open_findings(self) -> None:
        sid = self._current_id()
        if not sid:
            self.app.notify("Select a scan first", title="Vault")  # type: ignore[attr-defined]
            return
        self.app.push_screen(FindingsScreen(scan_id=sid))  # type: ignore[attr-defined]

    def action_show_paths(self) -> None:
        sid = self._current_id()
        if not sid:
            self.app.notify("Select a scan first", title="Vault")  # type: ignore[attr-defined]
            return
        self._update_paths(sid)

    def _update_paths(self, scan_id: str) -> None:
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        try:
            entry = vault.get_entry(scan_id)
            html = vault.report_path(scan_id, "html")
            md = vault.report_path(scan_id, "md")
            js = vault.report_path(scan_id, "json")
        except (LookupError, VaultSafetyError, ValueError, FileNotFoundError) as exc:
            self.query_one("#vault-paths", Static).update(f"Paths unavailable: {exc}")
            return
        self.query_one("#vault-paths", Static).update(
            f"Scan …{entry.scan_id[-10:]}\n"
            f"Dir   {entry.path}\n"
            f"HTML  {html}\n"
            f"MD    {md}\n"
            f"JSON  {js}\n"
            f"raw/  {entry.path}/raw/"
        )

    def action_add_tag(self) -> None:
        sid = self._current_id()
        tag = self.query_one("#vault-tag", Input).value.strip()
        if not sid or not tag:
            self.app.notify("Select a scan and enter a tag", title="Vault")  # type: ignore[attr-defined]
            return
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        tags = vault.add_tag(sid, tag)
        self.refresh_list()
        self.app.notify(f"Tags: {', '.join(tags)}", title="Vault")  # type: ignore[attr-defined]

    def action_diff_selected(self) -> None:
        if len(self._selected) != 2:
            # Fall back to cursor + previous selection hint
            sid = self._current_id()
            if sid and sid not in self._selected:
                self._selected.append(sid)
            if len(self._selected) != 2:
                self.app.notify(  # type: ignore[attr-defined]
                    "Select exactly two scans (Enter on each row)",
                    title="Vault",
                )
                return
        a, b = self._selected[0], self._selected[1]
        self.app.push_screen(DiffScreen(a, b))  # type: ignore[attr-defined]

    def action_delete_scan(self) -> None:
        sid = self._current_id()
        if not sid:
            return

        def _done(confirmed: bool | None) -> None:
            if not confirmed:
                self.app.notify("Delete cancelled", title="Vault")  # type: ignore[attr-defined]
                return
            vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
            try:
                dest = vault.soft_delete(sid, confirm_id=sid[-8:])
            except VaultSafetyError as exc:
                self.app.notify(str(exc), title="Vault", severity="error")  # type: ignore[attr-defined]
                return
            self.refresh_list()
            self.app.notify(f"Moved to trash: {dest.name}", title="Vault")  # type: ignore[attr-defined]

        self.app.push_screen(ConfirmDeleteScreen(sid), _done)  # type: ignore[attr-defined]
