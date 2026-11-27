"""Phase 8 TUI snapshots and pilot flows."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.models import (
    BackendKind,
    Category,
    Finding,
    FindingStatus,
    HostInfo,
    PluginResult,
    PluginStatus,
    Scan,
    Severity,
)
from wardline.core.scoring import build_scores, build_summary
from wardline.tui.app import WardlineApp
from wardline.tui.screens.baseline_dialog import BaselineDialog
from wardline.tui.screens.diff_view import DiffScreen
from wardline.tui.screens.findings import FindingsScreen
from wardline.tui.screens.vault_browser import ConfirmDeleteScreen, VaultScreen
from wardline.vault.store import VaultStore


def _scan(scan_id: str, *, title: str = "Unexplained listener") -> Scan:
    findings = [
        Finding(
            scan_id=scan_id,
            host="lab01.example.internal",
            plugin="ss_baseline",
            rule_id="SS-LISTEN-8080-tcp",
            category=Category.NETWORK,
            severity=Severity.MEDIUM,
            title=title,
            location="192.0.2.10:8080",
            description="demo finding",
            evidence="tcp LISTEN 192.0.2.10:8080",
        )
    ]
    return Scan(
        id=scan_id,
        wardline_version="0.1.0",
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        finished_at=datetime(2024, 6, 1, 12, 5, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.LOCAL,
        host=HostInfo(hostname="lab01.example.internal", distro="debian", version="12"),
        plugin_results=[
            PluginResult(plugin="ss_baseline", status=PluginStatus.FINDINGS, exit_code=0)
        ],
        findings=findings,
        summary=build_summary(findings),
        scores=build_scores(findings),
        tags=["lab"],
    )


def _app(tmp_path: Path, *, start: str, seed: int = 1) -> WardlineApp:
    vault = VaultStore(tmp_path / "vault")
    ids = [
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    ]
    for i in range(seed):
        vault.save(_scan(ids[i], title=f"Finding {i}"))
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True
    return WardlineApp(
        config=cfg,
        vault=vault,
        start=start,
        auto_advance=False,
        demo_mode=True,
        findings_scan_id=ids[0] if seed else None,
    )


async def _settle(pilot) -> None:  # type: ignore[no-untyped-def]
    await pilot.pause(0.35)


def test_findings_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="findings")
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


def test_vault_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="vault", seed=2)
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


def test_evidence_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="evidence", seed=0)
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


def test_settings_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="settings", seed=0)
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


@pytest.mark.asyncio
async def test_findings_mark_resolved_pilot(tmp_path: Path) -> None:
    app = _app(tmp_path, start="findings")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        screen = app.screen
        assert isinstance(screen, FindingsScreen)
        screen.action_mark_resolved()
        await pilot.pause(0.2)
        scan = app.vault.load_scan("01ARZ3NDEKTSV4RRFFQ69G5FAV")
        assert scan.findings[0].status == FindingStatus.RESOLVED


@pytest.mark.asyncio
async def test_vault_open_findings_pilot(tmp_path: Path) -> None:
    app = _app(tmp_path, start="vault", seed=1)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        screen.action_open_findings()
        await pilot.pause(0.3)
        assert isinstance(app.screen, FindingsScreen)


@pytest.mark.asyncio
async def test_diff_screen_pilot(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "vault")
    a = _scan("01ARZ3NDEKTSV4RRFFQ69G5FAV")
    b = _scan("01ARZ3NDEKTSV4RRFFQ69G5FB0", title="Changed title")
    # Force different finding id for NEW by changing rule
    b.findings[0] = Finding(
        scan_id=b.id,
        host=b.host.hostname,
        plugin="ss_baseline",
        rule_id="SS-LISTEN-9090-tcp",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        title="New listener",
        location="192.0.2.10:9090",
    )
    b.summary = build_summary(b.findings)
    b.scores = build_scores(b.findings)
    vault.save(a)
    vault.save(b)
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True
    app = WardlineApp(config=cfg, vault=vault, start="vault", demo_mode=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        app.push_screen(DiffScreen(a.id, b.id))
        await pilot.pause(0.3)
        assert isinstance(app.screen, DiffScreen)
        summary = str(app.screen.query_one("#diff-summary").render())
        assert "new=" in summary


@pytest.mark.asyncio
async def test_typed_delete_confirm_screen(tmp_path: Path) -> None:
    app = _app(tmp_path, start="vault")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        sid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        result: list[bool | None] = []

        def _cb(value: bool | None) -> None:
            result.append(value)

        app.push_screen(ConfirmDeleteScreen(sid), _cb)
        await pilot.pause(0.2)
        screen = app.screen
        assert isinstance(screen, ConfirmDeleteScreen)
        screen.query_one("#confirm-input").value = sid[-8:]  # type: ignore[attr-defined]
        screen.query_one("#btn-delete").press()  # type: ignore[attr-defined]
        await pilot.pause(0.2)
        assert result == [True]


@pytest.mark.asyncio
async def test_baseline_dialog_opens(tmp_path: Path) -> None:
    app = _app(tmp_path, start="settings", seed=0)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        app.push_screen(BaselineDialog())
        await pilot.pause(0.2)
        assert isinstance(app.screen, BaselineDialog)
