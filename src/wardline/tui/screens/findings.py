"""Findings Explorer — filter, detail, status/note actions."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, Static

from wardline.core.models import Finding, FindingStatus, Scan
from wardline.tui.widgets.header import WardHeader
from wardline.vault.evidence import EvidenceError, EvidenceLocker
from wardline.vault.store import VaultStore


class FindingsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "app.pop_screen", "Back"),
        ("o", "mark_open", "Open"),
        ("a", "mark_accepted", "Accept risk"),
        ("r", "mark_resolved", "Resolved"),
        ("n", "focus_note", "Note"),
        ("e", "copy_evidence", "Evidence"),
    ]

    def __init__(self, scan_id: str | None = None) -> None:
        super().__init__()
        self._scan_id = scan_id
        self._scan: Scan | None = None
        self._rows: list[Finding] = []
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        yield WardHeader()
        with Vertical(id="findings-body"):
            yield Static("Findings Explorer — saved scan results", id="brand")
            yield Static("", id="find-scan-meta", classes="muted")
            with Horizontal(classes="filter-row"):
                yield Select(
                    [("loading…", "none")],
                    value="none",
                    id="find-scan",
                    allow_blank=False,
                )
                yield Input(placeholder="Search…", id="find-search")
                yield Select(
                    [
                        ("all severities", "all"),
                        ("critical", "critical"),
                        ("high", "high"),
                        ("medium", "medium"),
                        ("low", "low"),
                        ("info", "info"),
                    ],
                    value="all",
                    id="find-sev",
                    allow_blank=False,
                )
                yield Select(
                    [
                        ("all statuses", "all"),
                        ("open", "open"),
                        ("accepted_risk", "accepted_risk"),
                        ("resolved", "resolved"),
                    ],
                    value="all",
                    id="find-status",
                    allow_blank=False,
                )
            yield DataTable(id="find-table", cursor_type="row", zebra_stripes=True)
            yield Static("Select a finding", id="find-detail", classes="panel")
            yield Input(placeholder="User note for selected finding", id="find-note")
            with Horizontal():
                yield Button("Save note", id="btn-save-note")
                yield Button("Copy to Evidence Locker", id="btn-evidence")
                yield Button("Show report paths", id="btn-paths")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#find-table", DataTable)
        table.add_columns("Sev", "Plugin", "Title", "Status", "Verdict")
        self._populate_scan_select()
        self._load_scan()
        self._refresh_table()

    def _populate_scan_select(self) -> None:
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        entries = vault.list_scans(limit=30)
        options: list[tuple[str, str]] = []
        for entry in entries:
            label = (
                f"…{entry.scan_id[-8:]}  {entry.host}  "
                f"{entry.started_at.replace('T', ' ')[:16]}  posture {entry.posture}"
            )
            options.append((label, entry.scan_id))
        select = self.query_one("#find-scan", Select)
        if not options:
            select.set_options([("no scans yet", "none")])
            select.value = "none"
            return
        select.set_options(options)
        if self._scan_id and any(sid == self._scan_id for _, sid in options):
            select.value = self._scan_id
        else:
            select.value = options[0][1]
            self._scan_id = options[0][1]

    def _load_scan(self) -> None:
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        scan_id = self._scan_id
        if not scan_id or scan_id in {"none", "latest"}:
            entries = vault.list_scans(limit=1)
            if not entries:
                self._scan = None
                self._scan_id = None
                self.query_one("#find-scan-meta", Static).update("No saved scans in the Vault.")
                return
            scan_id = entries[0].scan_id
            self._scan_id = scan_id
        self._scan = vault.load_scan(scan_id)
        try:
            entry = vault.get_entry(scan_id)
            self.query_one("#find-scan-meta", Static).update(
                f"Saved scan …{entry.scan_id[-10:]} · {entry.host} · {entry.profile} · "
                f"posture {entry.posture}\nPath: {entry.path}"
            )
        except LookupError:
            self.query_one("#find-scan-meta", Static).update(f"Scan {scan_id}")

    def _refresh_table(self) -> None:
        table = self.query_one("#find-table", DataTable)
        table.clear()
        self._rows = []
        if not self._scan:
            self.query_one("#find-detail", Static).update("No scans in the Vault yet.")
            return
        search = self.query_one("#find-search", Input).value.strip().lower()
        sev = str(self.query_one("#find-sev", Select).value)
        status = str(self.query_one("#find-status", Select).value)
        for finding in self._scan.findings:
            if sev != "all" and finding.severity.value != sev:
                continue
            if status != "all" and finding.status.value != status:
                continue
            blob = f"{finding.title} {finding.plugin} {finding.rule_id} {finding.location}".lower()
            if search and search not in blob:
                continue
            self._rows.append(finding)
            table.add_row(
                finding.severity.value,
                finding.plugin,
                finding.title[:60],
                finding.status.value,
                finding.verdict.value,
                key=finding.id,
            )
        if self._rows:
            self._show_detail(self._rows[0])

    def _show_detail(self, finding: Finding) -> None:
        self._selected_id = finding.id
        cves = ", ".join(finding.cve_ids) if finding.cve_ids else "—"
        related = ", ".join(finding.related[:6]) if finding.related else "—"
        text = (
            f"[b]{finding.title}[/b]\n"
            f"{finding.severity.value} · {finding.category.value} · {finding.plugin} / {finding.rule_id}\n"
            f"Location: {finding.location}\n"
            f"Status: {finding.status.value} · Verdict: {finding.verdict.value}\n"
            f"{finding.verdict_reason}\n\n"
            f"{finding.description}\n\n"
            f"CVEs: {cves}\n"
            f"Fix: {finding.fix_hint or '—'}\n"
            f"Related: {related}\n"
            f"Note: {finding.user_note or '—'}\n\n"
            f"Evidence:\n{finding.evidence or '—'}"
        )
        self.query_one("#find-detail", Static).update(text)
        self.query_one("#find-note", Input).value = finding.user_note

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        fid = str(event.row_key.value)
        finding = next((f for f in self._rows if f.id == fid), None)
        if finding:
            self._show_detail(finding)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "find-search":
            self._refresh_table()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "find-scan":
            value = str(event.value)
            if value and value not in {"Select.BLANK", "none", "latest"}:
                if value == self._scan_id and self._scan is not None:
                    return
                self._scan_id = value
                self._load_scan()
                self._refresh_table()
        elif event.select.id in {"find-sev", "find-status"}:
            self._refresh_table()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save-note":
            self._save_note()
        elif event.button.id == "btn-evidence":
            self.action_copy_evidence()
        elif event.button.id == "btn-paths":
            self.action_show_paths()

    def action_show_paths(self) -> None:
        if not self._scan_id:
            return
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        try:
            html = vault.report_path(self._scan_id, "html")
            md = vault.report_path(self._scan_id, "md")
            js = vault.report_path(self._scan_id, "json")
        except (LookupError, ValueError, FileNotFoundError) as exc:
            self.app.notify(str(exc), title="Reports", severity="warning")  # type: ignore[attr-defined]
            return
        self.app.notify(  # type: ignore[attr-defined]
            f"HTML {html}\nMD {md}\nJSON {js}",
            title="Report paths",
            timeout=8,
        )

    def action_focus_note(self) -> None:
        self.query_one("#find-note", Input).focus()

    def action_mark_open(self) -> None:
        self._set_status(FindingStatus.OPEN)

    def action_mark_accepted(self) -> None:
        self._set_status(FindingStatus.ACCEPTED_RISK)

    def action_mark_resolved(self) -> None:
        self._set_status(FindingStatus.RESOLVED)

    def _set_status(self, status: FindingStatus) -> None:
        if not self._scan_id or not self._selected_id:
            return
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        vault.update_finding(self._scan_id, self._selected_id, status=status.value)
        self._load_scan()
        self._refresh_table()
        self.app.notify(f"Status → {status.value}", title="Finding")  # type: ignore[attr-defined]

    def _save_note(self) -> None:
        if not self._scan_id or not self._selected_id:
            return
        note = self.query_one("#find-note", Input).value
        vault: VaultStore = self.app.vault  # type: ignore[attr-defined]
        vault.update_finding(self._scan_id, self._selected_id, user_note=note)
        self._load_scan()
        self._refresh_table()
        self.app.notify("Note saved", title="Finding")  # type: ignore[attr-defined]

    def action_copy_evidence(self) -> None:
        if not self._scan or not self._selected_id:
            return
        finding = next((f for f in self._scan.findings if f.id == self._selected_id), None)
        if not finding:
            return
        path = finding.location
        cfg = self.app.ward_config  # type: ignore[attr-defined]
        locker = EvidenceLocker(config=cfg.evidence)
        try:
            item = locker.copy_file(
                Path(path),
                finding_id=finding.id,
                scan_id=self._scan.id,
            )
        except EvidenceError as exc:
            self.app.notify(str(exc), title="Evidence", severity="warning")  # type: ignore[attr-defined]
            return
        except OSError as exc:
            self.app.notify(f"Cannot copy: {exc}", title="Evidence", severity="error")  # type: ignore[attr-defined]
            return
        self.app.notify(f"Copied → {item.sha256[:12]}…", title="Evidence")  # type: ignore[attr-defined]
