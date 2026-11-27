"""Fleet scan concurrency and per-host isolation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from wardline.core.engine import ScanRunOutcome
from wardline.core.fleet import run_fleet_scan
from wardline.core.hosts import HostInventory, HostRecord
from wardline.core.models import (
    BackendKind,
    HostInfo,
    PluginResult,
    PluginStatus,
    Scan,
    ScanScores,
    ScanSummary,
)


def _outcome(host: str) -> ScanRunOutcome:
    scan = Scan(
        id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        wardline_version="0.1.0",
        started_at=datetime(2024, 6, 1, tzinfo=UTC),
        finished_at=datetime(2024, 6, 1, tzinfo=UTC),
        profile="quick",
        backend=BackendKind.SSH,
        host=HostInfo(hostname=host),
        plugin_results=[PluginResult(plugin="ss_baseline", status=PluginStatus.OK)],
        findings=[],
        summary=ScanSummary(),
        scores=ScanScores(posture=100),
    )
    return ScanRunOutcome(scan=scan)


@pytest.mark.asyncio
async def test_fleet_respects_concurrency(tmp_path: Path) -> None:
    inv = HostInventory(
        fleet_concurrency=2,
        hosts=[
            HostRecord(name=f"h{i}", host=f"192.0.2.{i}", use_sudo=False) for i in range(1, 5)
        ],
    )
    current = 0
    max_seen = 0
    lock = asyncio.Lock()

    async def fake_run_scan(backend: Any, **kwargs: Any) -> ScanRunOutcome:
        del kwargs
        nonlocal current, max_seen
        async with lock:
            current += 1
            max_seen = max(max_seen, current)
        await asyncio.sleep(0.05)
        async with lock:
            current -= 1
        return _outcome(backend.record.name)

    with (
        patch("wardline.core.fleet.SSHBackend.connect", new=AsyncMock()),
        patch("wardline.core.fleet.SSHBackend.close", new=AsyncMock()),
        patch("wardline.core.fleet.run_scan", new=AsyncMock(side_effect=fake_run_scan)),
        patch("wardline.core.fleet.VaultStore"),
    ):
        result = await run_fleet_scan(
            inv, profile="quick", save=False, known_hosts=tmp_path / "known_hosts"
        )

    assert result.ok_count == 4
    assert max_seen <= 2


@pytest.mark.asyncio
async def test_fleet_isolates_host_failures(tmp_path: Path) -> None:
    inv = HostInventory(
        hosts=[
            HostRecord(name="ok", host="192.0.2.10", use_sudo=False),
            HostRecord(name="bad", host="192.0.2.11", use_sudo=False),
        ]
    )

    async def fake_run_scan(backend: Any, **kwargs: Any) -> ScanRunOutcome:
        del kwargs
        if backend.record.name == "bad":
            raise RuntimeError("boom")
        return _outcome(backend.record.name)

    with (
        patch("wardline.core.fleet.SSHBackend.connect", new=AsyncMock()),
        patch("wardline.core.fleet.SSHBackend.close", new=AsyncMock()),
        patch("wardline.core.fleet.run_scan", new=AsyncMock(side_effect=fake_run_scan)),
        patch("wardline.core.fleet.VaultStore"),
    ):
        result = await run_fleet_scan(inv, save=False, known_hosts=tmp_path / "known_hosts")

    assert result.ok_count == 1
    assert result.fail_count == 1
    bad = next(r for r in result.results if r.host_name == "bad")
    assert "boom" in bad.error
