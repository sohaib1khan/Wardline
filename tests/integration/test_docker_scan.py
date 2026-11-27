"""Optional live Docker scans — skipped when the daemon/container is unavailable."""

from __future__ import annotations

import shutil

import pytest

from wardline.backends.base import BackendError
from wardline.backends.docker import DockerBackend
from wardline.core.engine import run_scan
from wardline.plugins.base import get_registry


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    backend = DockerBackend()
    try:
        import asyncio

        asyncio.run(backend.ensure_ready())
    except BackendError:
        return False
    return True


@pytest.mark.asyncio
@pytest.mark.skipif(not _docker_ready(), reason="wardline-scanner container not running")
async def test_quick_scan_docker_backend() -> None:
    get_registry()
    backend = DockerBackend()
    outcome = await run_scan(backend, profile="quick", plugin_names=["ss_baseline"])
    assert outcome.scan.backend.value == "docker"
    assert outcome.scan.plugin_results


@pytest.mark.asyncio
@pytest.mark.skipif(not _docker_ready(), reason="wardline-scanner container not running")
async def test_standard_scan_docker_backend() -> None:
    get_registry()
    backend = DockerBackend()
    outcome = await run_scan(
        backend,
        profile="standard",
        plugin_names=["ss_baseline", "persistence"],
    )
    assert outcome.scan.backend.value == "docker"
    names = [r.plugin for r in outcome.scan.plugin_results]
    assert "ss_baseline" in names
