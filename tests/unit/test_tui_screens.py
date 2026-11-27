"""TUI snapshot and pilot tests for Phase 5 screens."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
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
from wardline.core.scoring import build_scores, build_summary
from wardline.tui.app import WardlineApp
from wardline.tui.screens.live import LiveScanScreen
from wardline.vault.store import VaultStore


def _demo_scan(scan_id: str = "01ARZ3NDEKTSV4RRFFQ69G5FAV") -> Scan:
    findings = [
        Finding(
            scan_id=scan_id,
            host="lab01.example.internal",
            plugin="ss_baseline",
            rule_id="SS-LISTEN-8080-tcp",
            category=Category.NETWORK,
            severity=Severity.MEDIUM,
            title="Unexplained listener 8080/tcp",
            location="192.0.2.10:8080",
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


def _app(tmp_path: Path, *, start: str, seed: bool = False) -> WardlineApp:
    vault = VaultStore(tmp_path / "vault")
    if seed:
        vault.save(_demo_scan())
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True
    return WardlineApp(
        config=cfg,
        vault=vault,
        start=start,
        auto_advance=False,
        splash_delay=0.01,
        demo_mode=True,
        splash_status=(
            "lab01.example.internal · debian 12 · x86_64 · user · 8192 MiB\n"
            "tools: 1 ready · 2 missing/unavailable · backend local"
            if start == "splash"
            else None
        ),
    )


async def _settle(pilot) -> None:  # type: ignore[no-untyped-def]
    await pilot.pause(0.3)


def test_splash_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="splash")
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


def test_dashboard_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="dashboard", seed=True)
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


def test_launcher_snapshot(snap_compare, tmp_path: Path) -> None:
    app = _app(tmp_path, start="launcher")
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


@pytest.mark.asyncio
async def test_splash_enter_goes_to_dashboard(tmp_path: Path) -> None:
    app = _app(tmp_path, start="splash")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        assert hasattr(screen, "action_continue")
        screen.action_continue()  # type: ignore[attr-defined]
        await pilot.pause(0.2)
        assert "Dashboard" in app.screen.__class__.__name__


@pytest.mark.asyncio
async def test_live_ss_baseline_saves_to_vault(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "vault")
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True

    class LiveOnlyApp(WardlineApp):
        def on_mount(self) -> None:
            self.theme = "textual-dark"
            self.push_screen(LiveScanScreen(profile="custom", plugins=["ss_baseline"]))

    app = LiveOnlyApp(config=cfg, vault=vault, start="live", auto_advance=False)
    async with app.run_test(size=(100, 30)) as pilot:
        for _ in range(100):
            screen = app.screen
            if hasattr(screen, "running") and screen.running is False:
                break
            await pilot.pause(0.05)
        assert vault.list_scans(), "expected live scan to save into the Vault"
        entry = vault.list_scans()[0]
        assert entry.profile in {"custom", "quick"}
