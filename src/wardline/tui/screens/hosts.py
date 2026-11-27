"""Hosts screen — inventory, test connection, accept host key, fleet overview."""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Static

from wardline.backends.ssh import SSHBackend, SSHHostKeyError, accept_host_key
from wardline.core.hosts import HostRecord, load_hosts
from wardline.tui.widgets.header import WardHeader
from wardline.vault.store import VaultStore


class AcceptKeyDialog(ModalScreen[bool]):
    def __init__(self, host: str, fingerprint: str) -> None:
        super().__init__()
        self._host = host
        self._fingerprint = fingerprint

    def compose(self) -> ComposeResult:
        with Vertical(id="accept-key-dialog", classes="panel"):
            yield Static("Unknown SSH host key")
            yield Static(f"Host: {self._host}", classes="muted")
            yield Static(f"Fingerprint:\n{self._fingerprint}", id="ak-fp")
            yield Static("Save this key to known_hosts?", classes="muted")
            with Horizontal():
                yield Button("Cancel", id="btn-cancel")
                yield Button("Accept & save", id="btn-accept", classes="-primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn-accept")


class HostsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("t", "test_host", "Test"),
        ("a", "accept_key", "Accept key"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._records: list[HostRecord] = []

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="hosts-body"):
            yield Static("Remote Hosts", id="brand")
            yield Static("", id="hosts-fleet", classes="panel")
            yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
            with Horizontal():
                yield Button("Test connection", id="btn-test", classes="-primary")
                yield Button("Accept host key", id="btn-accept")
                yield Button("Refresh", id="btn-refresh")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.add_columns("Name", "Host", "User", "Port", "Tags", "Last posture")
        self.refresh_hosts()

    def on_screen_resume(self) -> None:
        self.refresh_hosts()

    def refresh_hosts(self) -> None:
        inventory = load_hosts()
        self._records = list(inventory.hosts)
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        table = self.query_one("#hosts-table", DataTable)
        table.clear()
        fleet_lines = ["Fleet overview (latest Vault score per host):"]
        for record in self._records:
            latest = _latest_posture(vault, record)
            table.add_row(
                record.name,
                record.host,
                record.user,
                str(record.port),
                ",".join(record.tags) if record.tags else "",
                latest,
                key=record.name,
            )
            fleet_lines.append(f"  {record.name:16}  posture {latest}")
        if not self._records:
            fleet_lines.append("  (no hosts in hosts.toml)")
        self.query_one("#hosts-fleet", Static).update("\n".join(fleet_lines))

    def _current(self) -> HostRecord | None:
        table = self.query_one("#hosts-table", DataTable)
        if table.cursor_row is None or table.cursor_row < 0 or not self._records:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            return self._records[0]
        if key is None:
            return self._records[0]
        name = str(key.value)
        return next((r for r in self._records if r.name == name), None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-test":
            self.action_test_host()
        elif event.button.id == "btn-accept":
            self.action_accept_key()
        elif event.button.id == "btn-refresh":
            self.refresh_hosts()

    def action_test_host(self) -> None:
        record = self._current()
        if not record:
            self.app.notify("Select a host", title="Hosts")  # type: ignore[attr-defined]
            return
        self.run_worker(self._test(record), exclusive=True)

    def action_accept_key(self) -> None:
        record = self._current()
        if not record:
            return
        self.run_worker(self._accept(record), exclusive=True)

    async def _test(self, record: HostRecord) -> None:
        backend = SSHBackend(record)
        try:
            info = await backend.host_info()
            self.app.notify(  # type: ignore[attr-defined]
                f"OK {info.hostname} · {info.distro} {info.version}",
                title=record.name,
            )
        except SSHHostKeyError as exc:
            self.app.notify(str(exc), title="Host key", severity="warning")  # type: ignore[attr-defined]
            if exc.unknown and exc.fingerprint:
                accepted = await self.app.push_screen_wait(  # type: ignore[attr-defined]
                    AcceptKeyDialog(record.host, exc.fingerprint)
                )
                if accepted:
                    fp = await accept_host_key(record.host, port=record.port)
                    self.app.notify(f"Saved key {fp}", title="Hosts")  # type: ignore[attr-defined]
        except Exception as exc:
            self.app.notify(f"Failed: {exc}", title=record.name, severity="error")  # type: ignore[attr-defined]
        finally:
            await backend.close()

    async def _accept(self, record: HostRecord) -> None:
        from wardline.backends.ssh import fetch_host_key_fingerprint

        try:
            fingerprint, _ = await fetch_host_key_fingerprint(record.host, port=record.port)
        except Exception as exc:
            self.app.notify(f"Fetch failed: {exc}", title="Hosts", severity="error")  # type: ignore[attr-defined]
            return
        accepted = await self.app.push_screen_wait(  # type: ignore[attr-defined]
            AcceptKeyDialog(record.host, fingerprint)
        )
        if not accepted:
            return
        fp = await accept_host_key(record.host, port=record.port)
        self.app.notify(f"Saved key {fp}", title="Hosts")  # type: ignore[attr-defined]


def _latest_posture(vault: VaultStore, record: HostRecord) -> str:
    # Match by inventory name, alias, or hostname substring in vault entries.
    candidates = {record.name, record.alias, record.host}
    candidates = {c for c in candidates if c}
    entries = vault.list_scans(limit=100)
    for entry in entries:
        if entry.host in candidates or any(c in entry.host for c in candidates):
            return str(entry.posture)
    return "—"
