"""Phase 10 Hosts screen snapshot + dashboard fleet panel."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.hosts import HostInventory, HostRecord, save_hosts
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
from wardline.core.paths import ENV_CONFIG_DIR
from wardline.core.scoring import build_scores, build_summary
from wardline.tui.app import WardlineApp
from wardline.tui.screens.hosts import HostsScreen
from wardline.vault.store import VaultStore


def _scan(host: str, scan_id: str) -> Scan:
    findings = [
        Finding(
            scan_id=scan_id,
            host=host,
            plugin="ss_baseline",
            rule_id="SS-LISTEN-22-tcp",
            category=Category.NETWORK,
            severity=Severity.INFO,
            title="Listener",
            location="0.0.0.0:22",
        )
    ]
    return Scan(
        id=scan_id,
        wardline_version="0.1.0",
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        finished_at=datetime(2024, 6, 1, 12, 5, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.SSH,
        host=HostInfo(hostname=host, distro="debian"),
        plugin_results=[PluginResult(plugin="ss_baseline", status=PluginStatus.OK)],
        findings=findings,
        summary=build_summary(findings),
        scores=build_scores(findings),
    )


async def _settle(pilot) -> None:  # type: ignore[no-untyped-def]
    await pilot.pause(0.35)


def test_hosts_snapshot(snap_compare, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setenv(ENV_CONFIG_DIR, str(cfg_dir))
    save_hosts(
        HostInventory(
            hosts=[
                HostRecord(
                    name="lab01",
                    host="192.0.2.10",
                    user="wardline",
                    tags=["lab"],
                )
            ]
        )
    )
    vault = VaultStore(tmp_path / "vault")
    vault.save(_scan("lab01.example.internal", "01ARZ3NDEKTSV4RRFFQ69G5FAV"))
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True
    app = WardlineApp(config=cfg, vault=vault, start="hosts", demo_mode=True)
    assert snap_compare(app, terminal_size=(100, 30), run_before=_settle)


@pytest.mark.asyncio
async def test_hosts_screen_lists_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setenv(ENV_CONFIG_DIR, str(cfg_dir))
    save_hosts(
        HostInventory(hosts=[HostRecord(name="lab01", host="192.0.2.10", user="wardline")])
    )
    vault = VaultStore(tmp_path / "vault")
    cfg = WardlineConfig()
    cfg.ui.reduce_motion = True
    app = WardlineApp(config=cfg, vault=vault, start="hosts", demo_mode=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        assert isinstance(app.screen, HostsScreen)
        assert app.screen._records[0].name == "lab01"
