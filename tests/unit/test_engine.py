"""Tests for the plugin runner / event bus integration."""

from __future__ import annotations

import pytest

from wardline.backends.local import LocalBackend
from wardline.core.engine import SKIP_NEEDS_ROOT, run_plugin
from wardline.core.events import EventBus, EventKind
from wardline.core.models import Category, PluginStatus
from wardline.plugins.base import DetectResult, ParseResult, Plugin
from wardline.plugins.dummy import DummyPlugin


class NeedsRootPlugin(Plugin):
    name = "needs_root_test"
    display_name = "Needs Root Test"
    category = Category.HARDENING
    description = "test only"
    needs_root = True
    hidden = True
    default_timeout = 10.0

    async def detect(self, backend):  # type: ignore[no-untyped-def]
        return DetectResult(installed=True, version="1")

    def install_hint(self, distro):  # type: ignore[no-untyped-def]
        return []

    def build_commands(self, backend, options=None):  # type: ignore[no-untyped-def]
        return [["true"]]

    def parse(self, raw_output, exit_code, *, scan_id, host, options=None):  # type: ignore[no-untyped-def]
        return ParseResult()


@pytest.mark.asyncio
async def test_run_dummy_ok_emits_events() -> None:
    backend = LocalBackend(apply_priority=False)
    bus = EventBus()
    plugin = DummyPlugin()

    outcome = await run_plugin(
        plugin,
        backend,
        scan_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        host="lab01.example.internal",
        bus=bus,
        options={"mode": "echo"},
    )

    assert outcome.result.status in {PluginStatus.OK, PluginStatus.FINDINGS}
    assert outcome.result.exit_code == 0
    assert any(f.rule_id == "DUMMY-001" for f in outcome.findings)

    kinds = [e.kind for e in bus.history]
    assert EventKind.PLUGIN_STARTED in kinds
    assert EventKind.OUTPUT_LINE in kinds
    assert EventKind.PLUGIN_FINISHED in kinds


@pytest.mark.asyncio
async def test_run_dummy_fail() -> None:
    backend = LocalBackend(apply_priority=False)
    outcome = await run_plugin(
        DummyPlugin(),
        backend,
        scan_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        host="lab01.example.internal",
        options={"mode": "fail"},
    )
    assert outcome.result.status == PluginStatus.FAILED
    assert outcome.result.exit_code != 0


@pytest.mark.asyncio
async def test_run_timeout() -> None:
    backend = LocalBackend(apply_priority=False)
    outcome = await run_plugin(
        DummyPlugin(),
        backend,
        scan_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        host="lab01.example.internal",
        options={"mode": "sleep", "seconds": "30"},
        timeout=0.3,
    )
    assert outcome.result.status == PluginStatus.TIMED_OUT


@pytest.mark.asyncio
async def test_skip_needs_root_when_not_root() -> None:
    backend = LocalBackend(apply_priority=False)
    if backend.is_root():
        pytest.skip("running as root; cannot test skip-needs-root path")

    outcome = await run_plugin(
        NeedsRootPlugin(),
        backend,
        scan_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        host="lab01.example.internal",
    )
    assert outcome.result.status == PluginStatus.SKIPPED
    assert outcome.result.skip_reason == SKIP_NEEDS_ROOT
