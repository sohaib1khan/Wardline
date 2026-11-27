"""Integration-ish tests for scan orchestration and CLI."""

from __future__ import annotations

import pytest
from rich.console import Console

from wardline.backends.local import LocalBackend
from wardline.cli.scan import run_scan_command
from wardline.core.engine import run_scan
from wardline.core.profiles import resolve_plugin_names
from wardline.plugins.base import get_registry


def test_resolve_plugins_override_profile() -> None:
    assert resolve_plugin_names(plugins=["ss_baseline"]) == ["ss_baseline"]
    assert "trivy" in resolve_plugin_names(profile="quick")


def test_registry_has_phase3_plugins() -> None:
    registry = get_registry(refresh=True)
    for name in ("ss_baseline", "lynis", "trivy"):
        assert name in registry


@pytest.mark.asyncio
async def test_run_scan_ss_only() -> None:
    backend = LocalBackend(apply_priority=False)
    outcome = await run_scan(backend, plugin_names=["ss_baseline"], profile="custom")
    scan = outcome.scan
    assert scan.plugin_results
    assert scan.plugin_results[0].plugin == "ss_baseline"
    assert scan.plugin_results[0].status.value in {
        "ok",
        "findings",
        "failed",
        "unavailable",
        "skipped",
        "timed_out",
    }
    # ss is installed on this lab host — expect a real run.
    assert scan.plugin_results[0].status.value in {"ok", "findings"}


def test_scan_cli_ss_baseline() -> None:
    console = Console(record=True, width=120)
    code = run_scan_command(plugins="ss_baseline", no_save=True, console=console)
    assert code in {0, 1}
    text = console.export_text()
    assert "Wardline scan" in text
    assert "ss_baseline" in text
    assert "posture=" in text or "posture" in text.lower() or "Scan" in text
