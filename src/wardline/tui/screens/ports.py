"""Expected listeners CRUD — ports for ss_baseline unexplained-listener checks."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Static

from wardline.core.config import save_config
from wardline.core.ports import PortError, normalize_listener
from wardline.tui.widgets.header import WardHeader


class PortsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("a", "add_port", "Add"),
        ("x", "remove_port", "Remove"),
        ("s", "save", "Save"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._ports: list[str] = []

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="ports-body"):
            yield Static("Expected ports", id="ports-title")
            yield Static(
                "Listeners Wardline expects (ss_baseline). Unexpected → medium finding.",
                classes="muted",
            )
            yield DataTable(id="ports-table", cursor_type="row", zebra_stripes=True)
            yield Input(placeholder="Add port — e.g. 22/tcp or 53/udp", id="ports-input")
            with Horizontal():
                yield Button("Add", id="btn-add", classes="-primary")
                yield Button("Remove selected", id="btn-remove")
                yield Button("Save", id="btn-save")
                yield Button("Close", id="btn-close")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ports-table", DataTable)
        table.add_columns("#", "Port/proto")
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        self._ports = list(cfg.scan.ss.expected_listeners)
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one("#ports-table", DataTable)
        table.clear()
        for i, port in enumerate(self._ports, start=1):
            table.add_row(str(i), port, key=port)

    def _current(self) -> str | None:
        table = self.query_one("#ports-table", DataTable)
        if table.cursor_row is None or table.cursor_row < 0:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        if row_key is None:
            return None
        return str(row_key.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-add":
            self.action_add_port()
        elif event.button.id == "btn-remove":
            self.action_remove_port()
        elif event.button.id == "btn-save":
            self.action_save()
        elif event.button.id == "btn-close":
            self.app.pop_screen()

    def action_add_port(self) -> None:
        raw = self.query_one("#ports-input", Input).value
        try:
            norm = normalize_listener(raw)
        except PortError as exc:
            self.app.notify(str(exc), title="Ports", severity="error")  # type: ignore[attr-defined]
            return
        if norm in self._ports:
            self.app.notify(f"Already listed: {norm}", title="Ports")  # type: ignore[attr-defined]
            return
        self._ports.append(norm)
        self.query_one("#ports-input", Input).value = ""
        self._refresh()
        self.app.notify(f"Added {norm} (not saved yet)", title="Ports")  # type: ignore[attr-defined]

    def action_remove_port(self) -> None:
        current = self._current()
        if not current:
            self.app.notify("Select a port row first", title="Ports")  # type: ignore[attr-defined]
            return
        self._ports = [p for p in self._ports if p != current]
        self._refresh()
        self.app.notify(f"Removed {current} (not saved yet)", title="Ports")  # type: ignore[attr-defined]

    def action_save(self) -> None:
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        cfg.scan.ss.expected_listeners = list(self._ports)
        try:
            path = save_config(cfg)
            self.app.notify(f"Saved {path}", title="Ports")  # type: ignore[attr-defined]
        except OSError as exc:
            self.app.notify(  # type: ignore[attr-defined]
                f"In-memory only ({exc})",
                title="Ports",
                severity="warning",
            )
