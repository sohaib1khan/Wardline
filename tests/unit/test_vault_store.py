"""Vault store save/list/load/tag/delete tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.core.models import (
    BackendKind,
    Category,
    Finding,
    HostInfo,
    PluginResult,
    PluginStatus,
    Scan,
    Severity,
)
from wardline.core.paths import mode_octal
from wardline.core.scoring import build_scores, build_summary
from wardline.vault.safety import VaultSafetyError
from wardline.vault.store import VaultStore


def _scan(
    *, scan_id: str = "01ARZ3NDEKTSV4RRFFQ69G5FAV", host: str = "lab01.example.internal"
) -> Scan:
    findings = [
        Finding(
            scan_id=scan_id,
            host=host,
            plugin="ss_baseline",
            rule_id="SS-LISTEN-8080-tcp",
            category=Category.NETWORK,
            severity=Severity.MEDIUM,
            title="Unexplained listener 8080/tcp",
            location="192.0.2.10:8080",
            evidence="tcp LISTEN 192.0.2.10:8080",
        )
    ]
    summary = build_summary(findings)
    scores = build_scores(findings)
    return Scan(
        id=scan_id,
        wardline_version="0.1.0",
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        finished_at=datetime(2024, 6, 1, 12, 5, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.LOCAL,
        host=HostInfo(hostname=host, distro="debian", version="12", arch="x86_64"),
        plugin_results=[
            PluginResult(plugin="ss_baseline", status=PluginStatus.FINDINGS, exit_code=0)
        ],
        findings=findings,
        summary=summary,
        scores=scores,
        tags=[],
    )


def test_save_creates_reports_and_index(tmp_path: Path) -> None:
    store = VaultStore(tmp_path / "vault")
    path = store.save(_scan(), raw_by_plugin={"ss_baseline": "raw ss output\n"})
    assert (path / "scan.json").is_file()
    assert (path / "report.md").is_file()
    assert (path / "report.html").is_file()
    assert (path / "notes.md").is_file()
    assert (path / "raw" / "ss_baseline.txt").is_file()
    assert mode_octal(path / "scan.json") == 0o600
    assert mode_octal(path) == 0o700

    html = (path / "report.html").read_text(encoding="utf-8")
    assert "WARDLINE" in html
    assert "lab01.example.internal" in html
    assert "http://" not in html  # no CDN / external refs
    assert "<script" not in html.lower()

    entries = store.list_scans()
    assert len(entries) == 1
    loaded = store.load_scan(entries[0].scan_id)
    assert loaded.findings[0].rule_id == "SS-LISTEN-8080-tcp"


def test_tag_and_soft_delete(tmp_path: Path) -> None:
    store = VaultStore(tmp_path / "vault")
    scan = _scan()
    store.save(scan)
    tags = store.add_tag(scan.id, "lab")
    assert "lab" in tags

    short = scan.id[-8:]
    with pytest.raises(VaultSafetyError, match="confirmation"):
        store.soft_delete(scan.id, confirm_id="nope")

    dest = store.soft_delete(scan.id, confirm_id=short)
    assert dest.exists()
    assert store.list_scans() == []


def test_load_by_suffix(tmp_path: Path) -> None:
    store = VaultStore(tmp_path / "vault")
    scan = _scan()
    store.save(scan)
    loaded = store.load_scan(scan.id[-10:])
    assert loaded.id == scan.id
