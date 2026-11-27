"""Vault filesystem store + SQLite index."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from wardline.core.models import Finding, Scan
from wardline.core.paths import (
    DIR_MODE,
    FILE_MODE,
    ensure_dir,
    ensure_file_perms,
    vault_root,
    write_private_file,
)
from wardline.reports.html import render_html
from wardline.reports.markdown import render_markdown
from wardline.vault.safety import VaultSafetyError, assert_inside_vault, soft_delete_report

_HOST_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(slots=True)
class VaultEntry:
    scan_id: str
    host: str
    profile: str
    started_at: str
    posture: int
    path: str
    tags: list[str]
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class VaultStore:
    """Save/load scans under the Vault root and maintain ``vault.db``."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root if root is not None else vault_root()).resolve()
        ensure_dir(self.root, mode=DIR_MODE)
        ensure_dir(self.root / ".trash", mode=DIR_MODE)
        self.db_path = self.root / "vault.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    host TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    posture INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '[]',
                    critical INTEGER NOT NULL DEFAULT 0,
                    high INTEGER NOT NULL DEFAULT 0,
                    medium INTEGER NOT NULL DEFAULT 0,
                    low INTEGER NOT NULL DEFAULT 0,
                    info INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    plugin TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                """
            )
        ensure_file_perms(self.db_path, FILE_MODE)

    def _report_dir(self, scan: Scan) -> Path:
        host = _HOST_SAFE.sub("_", scan.host.hostname) or "host"
        started = scan.started_at
        stamp = started.strftime("%Y-%m-%d_%H%M")
        short = scan.id[-10:]
        name = f"{stamp}_{scan.profile}_{short}"
        path = self.root / host / name
        return path

    def save(
        self,
        scan: Scan,
        *,
        raw_by_plugin: dict[str, str] | None = None,
        previous_scans: list[Scan] | None = None,
    ) -> Path:
        """Write scan.json / reports / raw outputs and index the scan."""
        report_dir = self._report_dir(scan)
        ensure_dir(report_dir.parent, mode=DIR_MODE)
        ensure_dir(report_dir, mode=DIR_MODE)
        assert_inside_vault(report_dir, self.root)

        write_private_file(
            report_dir / "scan.json",
            json.dumps(scan.model_dump(mode="json"), indent=2, sort_keys=False) + "\n",
        )
        write_private_file(report_dir / "report.md", render_markdown(scan))
        write_private_file(
            report_dir / "report.html",
            render_html(scan, previous_scans=previous_scans or []),
        )
        if not (report_dir / "notes.md").exists():
            write_private_file(report_dir / "notes.md", "# Notes\n\n")

        if raw_by_plugin:
            raw_dir = ensure_dir(report_dir / "raw", mode=DIR_MODE)
            for plugin, text in raw_by_plugin.items():
                safe = _HOST_SAFE.sub("_", plugin) or "plugin"
                write_private_file(raw_dir / f"{safe}.txt", text)

        self._upsert_index(scan, report_dir)
        return report_dir

    def _upsert_index(self, scan: Scan, report_dir: Path) -> None:
        sev = scan.summary.by_severity
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    id, host, profile, started_at, finished_at, posture, path, tags,
                    critical, high, medium, low, info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    host=excluded.host,
                    profile=excluded.profile,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    posture=excluded.posture,
                    path=excluded.path,
                    tags=excluded.tags,
                    critical=excluded.critical,
                    high=excluded.high,
                    medium=excluded.medium,
                    low=excluded.low,
                    info=excluded.info
                """,
                (
                    scan.id,
                    scan.host.hostname,
                    scan.profile,
                    scan.started_at.isoformat(),
                    scan.finished_at.isoformat() if scan.finished_at else None,
                    scan.scores.posture,
                    str(report_dir),
                    json.dumps(scan.tags),
                    sev.critical,
                    sev.high,
                    sev.medium,
                    sev.low,
                    sev.info,
                ),
            )
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan.id,))
            for finding in scan.findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, host, plugin, rule_id, severity, category,
                        title, status, verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.id,
                        scan.id,
                        finding.host,
                        finding.plugin,
                        finding.rule_id,
                        finding.severity.value,
                        finding.category.value,
                        finding.title,
                        finding.status.value,
                        finding.verdict.value,
                    ),
                )

    def list_scans(
        self,
        *,
        host: str | None = None,
        profile: str | None = None,
        tag: str | None = None,
        limit: int = 50,
    ) -> list[VaultEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if host:
            clauses.append("host = ?")
            params.append(host)
        if profile:
            clauses.append("profile = ?")
            params.append(profile)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM scans {where} ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        entries: list[VaultEntry] = []
        for row in rows:
            tags = json.loads(row["tags"] or "[]")
            if tag and tag not in tags:
                continue
            entries.append(
                VaultEntry(
                    scan_id=row["id"],
                    host=row["host"],
                    profile=row["profile"],
                    started_at=row["started_at"],
                    posture=row["posture"],
                    path=row["path"],
                    tags=tags,
                    critical=row["critical"],
                    high=row["high"],
                    medium=row["medium"],
                    low=row["low"],
                    info=row["info"],
                )
            )
        return entries

    def get_entry(self, scan_id: str) -> VaultEntry:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ? OR id LIKE ?",
                (scan_id, f"%{scan_id}"),
            ).fetchone()
        if row is None:
            # Also try short suffix match
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM scans").fetchall()
            matches = [r for r in rows if r["id"].endswith(scan_id) or scan_id in r["id"]]
            if len(matches) == 1:
                row = matches[0]
            elif len(matches) > 1:
                raise LookupError(f"ambiguous scan id prefix {scan_id!r}")
            else:
                raise LookupError(f"scan not found: {scan_id}")
        tags = json.loads(row["tags"] or "[]")
        return VaultEntry(
            scan_id=row["id"],
            host=row["host"],
            profile=row["profile"],
            started_at=row["started_at"],
            posture=row["posture"],
            path=row["path"],
            tags=tags,
            critical=row["critical"],
            high=row["high"],
            medium=row["medium"],
            low=row["low"],
            info=row["info"],
        )

    def load_scan(self, scan_id: str) -> Scan:
        entry = self.get_entry(scan_id)
        path = assert_inside_vault(Path(entry.path), self.root)
        scan_json = path / "scan.json"
        if not scan_json.is_file():
            raise FileNotFoundError(f"missing scan.json for {entry.scan_id}")
        data = json.loads(scan_json.read_text(encoding="utf-8"))
        return Scan.model_validate(data)

    def report_path(self, scan_id: str, fmt: str) -> Path:
        entry = self.get_entry(scan_id)
        path = assert_inside_vault(Path(entry.path), self.root)
        mapping = {
            "json": path / "scan.json",
            "md": path / "report.md",
            "markdown": path / "report.md",
            "html": path / "report.html",
        }
        try:
            target = mapping[fmt.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown format {fmt!r}; use json, md, html") from exc
        assert_inside_vault(target, self.root)
        return target

    def add_tag(self, scan_id: str, tag: str) -> list[str]:
        scan = self.load_scan(scan_id)
        if tag not in scan.tags:
            scan.tags.append(tag)
        self._rewrite_scan(scan)
        return list(scan.tags)

    def update_finding(
        self,
        scan_id: str,
        finding_id: str,
        *,
        status: str | None = None,
        user_note: str | None = None,
    ) -> Finding:
        """Update user-editable finding fields and rewrite the saved scan."""
        from wardline.core.models import FindingStatus
        from wardline.core.scoring import build_scores, build_summary

        scan = self.load_scan(scan_id)
        target = next((f for f in scan.findings if f.id == finding_id), None)
        if target is None:
            # Also allow short suffix match.
            matches = [f for f in scan.findings if f.id.endswith(finding_id)]
            if len(matches) != 1:
                raise LookupError(f"finding not found: {finding_id}")
            target = matches[0]
        if status is not None:
            target.status = FindingStatus(status)
        if user_note is not None:
            target.user_note = user_note
        scan.summary = build_summary(scan.findings)
        scan.scores = build_scores(
            scan.findings,
            lynis_hardening_index=scan.scores.lynis_hardening_index,
        )
        self._rewrite_scan(scan)
        return target

    def set_report_notes(self, scan_id: str, text: str) -> Path:
        entry = self.get_entry(scan_id)
        report_dir = assert_inside_vault(Path(entry.path), self.root)
        notes = report_dir / "notes.md"
        write_private_file(notes, text if text.endswith("\n") else text + "\n")
        return notes

    def read_report_notes(self, scan_id: str) -> str:
        entry = self.get_entry(scan_id)
        report_dir = assert_inside_vault(Path(entry.path), self.root)
        notes = report_dir / "notes.md"
        if not notes.is_file():
            return ""
        return notes.read_text(encoding="utf-8")

    def _rewrite_scan(self, scan: Scan) -> Path:
        entry = self.get_entry(scan.id)
        report_dir = assert_inside_vault(Path(entry.path), self.root)
        write_private_file(
            report_dir / "scan.json",
            json.dumps(scan.model_dump(mode="json"), indent=2) + "\n",
        )
        write_private_file(report_dir / "report.md", render_markdown(scan))
        write_private_file(report_dir / "report.html", render_html(scan))
        self._upsert_index(scan, report_dir)
        return report_dir

    def soft_delete(self, scan_id: str, *, confirm_id: str) -> Path:
        """Soft-delete after the caller confirms with the scan's short id."""
        entry = self.get_entry(scan_id)
        short = entry.scan_id[-8:]
        if confirm_id.strip() not in {entry.scan_id, short, entry.scan_id[-10:]}:
            raise VaultSafetyError(
                f"confirmation mismatch: type the scan id (or last 8 chars {short})"
            )
        report_dir = assert_inside_vault(Path(entry.path), self.root)
        dest = soft_delete_report(report_dir, self.root)
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (entry.scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (entry.scan_id,))
        return dest

    def apply_retention(self, *, keep_last_n: int) -> list[Path]:
        """Move older reports per host into trash when keep_last_n > 0."""
        if keep_last_n <= 0:
            return []
        trashed: list[Path] = []
        with self._connect() as conn:
            hosts = [r[0] for r in conn.execute("SELECT DISTINCT host FROM scans").fetchall()]
        for host in hosts:
            entries = self.list_scans(host=host, limit=10_000)
            for entry in entries[keep_last_n:]:
                report_dir = assert_inside_vault(Path(entry.path), self.root)
                dest = soft_delete_report(report_dir, self.root)
                with self._connect() as conn:
                    conn.execute("DELETE FROM findings WHERE scan_id = ?", (entry.scan_id,))
                    conn.execute("DELETE FROM scans WHERE id = ?", (entry.scan_id,))
                trashed.append(dest)
        return trashed

    def recent_for_host(self, host: str, *, limit: int = 5) -> list[Scan]:
        entries = self.list_scans(host=host, limit=limit)
        scans: list[Scan] = []
        for entry in entries:
            try:
                scans.append(self.load_scan(entry.scan_id))
            except (OSError, LookupError, ValueError):
                continue
        return scans


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)
