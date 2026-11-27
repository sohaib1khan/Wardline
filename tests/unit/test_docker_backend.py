"""DockerBackend path mapping and exec wiring (mocked docker CLI)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from wardline.backends.base import BackendError, CommandResult
from wardline.backends.docker import HOST_ROOT, DockerBackend
from wardline.core.capability_matrix import render_capability_matrix, write_capability_matrix
from wardline.plugins.base import get_registry
from wardline.plugins.chkrootkit import ChkrootkitPlugin
from wardline.plugins.clamav import ClamAVPlugin
from wardline.plugins.trivy import TrivyPlugin


def test_path_maps_host_root() -> None:
    backend = DockerBackend()
    assert backend.path("/") == HOST_ROOT
    assert backend.path("/etc/passwd") == f"{HOST_ROOT}/etc/passwd"
    assert backend.path(f"{HOST_ROOT}/etc/os-release") == f"{HOST_ROOT}/etc/os-release"
    assert backend.is_root() is True


def test_trivy_uses_host_rootfs_under_docker() -> None:
    backend = DockerBackend()
    cmds = TrivyPlugin().build_commands(backend, {})
    assert any("/host" in arg for cmd in cmds for arg in cmd)


def test_clamav_maps_paths() -> None:
    backend = DockerBackend()
    cmds = ClamAVPlugin().build_commands(backend, {"paths": ["/home", "/tmp"]})
    flat = cmds[0]
    assert f"{HOST_ROOT}/home" in flat
    assert f"{HOST_ROOT}/tmp" in flat


def test_chkrootkit_uses_root_prefix() -> None:
    backend = DockerBackend()
    cmds = ChkrootkitPlugin().build_commands(backend, {})
    assert cmds[0][:3] == ["chkrootkit", "-q", "-r"]
    assert cmds[0][3] == HOST_ROOT


@pytest.mark.asyncio
async def test_ensure_ready_requires_running_container() -> None:
    backend = DockerBackend(docker_bin="docker")

    async def fake_run_argv(argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        if "inspect" in argv:
            return CommandResult(exit_code=1, stdout="", stderr="missing", argv=argv)
        return CommandResult(exit_code=0, stdout="", stderr="", argv=argv)

    with (
        patch("wardline.backends.docker.shutil.which", return_value="/usr/bin/docker"),
        patch("wardline.backends.docker._run_argv", new=AsyncMock(side_effect=fake_run_argv)),
        pytest.raises(BackendError, match="not running"),
    ):
        await backend.ensure_ready()


@pytest.mark.asyncio
async def test_run_wraps_docker_exec() -> None:
    backend = DockerBackend(docker_bin="docker", apply_priority=False)
    captured: list[list[str]] = []

    async def fake_run_argv(argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        captured.append(list(argv))
        if "inspect" in argv:
            return CommandResult(exit_code=0, stdout="true\n", stderr="", argv=argv)
        return CommandResult(exit_code=0, stdout="ok", stderr="", argv=argv)

    with (
        patch("wardline.backends.docker.shutil.which", return_value="/usr/bin/docker"),
        patch("wardline.backends.docker._run_argv", new=AsyncMock(side_effect=fake_run_argv)),
    ):
        result = await backend.run(["ss", "-tulpn"], timeout=5.0)
    assert result.exit_code == 0
    exec_argv = captured[-1]
    assert exec_argv[:3] == ["docker", "exec", "wardline-scanner"] or (
        exec_argv[0] == "docker" and "exec" in exec_argv and "wardline-scanner" in exec_argv
    )
    assert exec_argv[-2:] == ["ss", "-tulpn"]


def test_capability_matrix_render_includes_plugins(tmp_path) -> None:  # type: ignore[no-untyped-def]
    text = render_capability_matrix(get_registry())
    assert "Trivy rootfs" in text
    assert "ss baseline" in text or "ss" in text.lower()
    assert "| Local | Docker | SSH |" in text
    out = write_capability_matrix(tmp_path / "capability-matrix.md")
    assert out.is_file()
    assert "full" in out.read_text(encoding="utf-8")
