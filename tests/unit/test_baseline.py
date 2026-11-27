"""Guarded Baseline — dirty pkg_verify blocks; clean allows plan."""

from __future__ import annotations

from typing import Any

import pytest

from wardline.backends.base import Backend, CommandResult
from wardline.core.baseline import plan_guarded_baseline, run_guarded_baseline
from wardline.core.models import BackendKind, HostInfo, Severity


class FakeBackend(Backend):
    kind = BackendKind.LOCAL

    def __init__(self, *, debsums_output: str = "", exit_code: int = 0, root: bool = True) -> None:
        self._debsums_output = debsums_output
        self._exit_code = exit_code
        self._root = root
        self.ran: list[list[str]] = []

    def prefix(self) -> list[str]:
        return []

    def path(self, host_path: str) -> str:
        return host_path

    def is_root(self) -> bool:
        return self._root

    async def run(
        self,
        cmd: list[str],
        *,
        timeout: float | None = None,
        needs_root: bool = False,
        env: dict[str, str] | None = None,
        on_line: Any = None,
        cwd: str | None = None,
    ) -> CommandResult:
        del timeout, needs_root, env, on_line, cwd
        self.ran.append(list(cmd))
        if cmd and cmd[0] == "debsums":
            return CommandResult(
                exit_code=self._exit_code,
                stdout=self._debsums_output,
                stderr="",
                argv=list(cmd),
            )
        if cmd and cmd[0] in {"aide", "aideinit", "rkhunter"}:
            return CommandResult(exit_code=0, stdout="ok", stderr="", argv=list(cmd))
        return CommandResult(exit_code=0, stdout="", stderr="", argv=list(cmd))

    async def read_file(self, path: str) -> bytes:
        raise FileNotFoundError(path)

    async def exists(self, path: str) -> bool:
        return False

    async def which(self, binary: str) -> str | None:
        if binary == "debsums":
            return "/usr/bin/debsums"
        if binary in {"aide", "rkhunter", "aideinit"}:
            return f"/usr/bin/{binary}"
        return None

    async def host_info(self) -> HostInfo:
        return HostInfo(hostname="testhost", distro="debian", is_root=self._root)


@pytest.mark.asyncio
async def test_dirty_pkg_verify_blocks_baseline() -> None:
    backend = FakeBackend(
        debsums_output="/usr/bin/sudo  FAILED\n",
        exit_code=2,
    )
    plan = await plan_guarded_baseline(
        backend,
        "aide",
        changed_paths=["/usr/bin/sudo"],
    )
    assert plan.blocked
    assert "/usr/bin/sudo" in plan.dirty_paths
    assert plan.critical_finding is not None
    assert plan.critical_finding.severity == Severity.CRITICAL
    assert "tamper" in plan.critical_finding.title.lower()
    assert plan.critical_finding.rule_id == "BASELINE-BLOCKED-TAMPER"


@pytest.mark.asyncio
async def test_dirty_blocks_even_with_yes() -> None:
    backend = FakeBackend(debsums_output="/usr/bin/sudo  FAILED\n", exit_code=2)
    result = await run_guarded_baseline(
        backend,
        "rkhunter",
        yes=True,
        changed_paths=["/usr/bin/sudo"],
    )
    assert result.plan.blocked
    assert not result.executed
    # Must never have run --propupd
    assert not any(cmd[:2] == ["rkhunter", "--propupd"] for cmd in backend.ran)


@pytest.mark.asyncio
async def test_clean_plan_dry_run_does_not_execute() -> None:
    backend = FakeBackend(debsums_output="", exit_code=0)
    result = await run_guarded_baseline(
        backend,
        "aide",
        yes=False,
        changed_paths=["/usr/bin/sudo"],
    )
    assert not result.plan.blocked
    assert not result.executed
    assert "--yes" in result.message or "Dry-run" in result.message
    assert not any(cmd[0] == "aide" for cmd in backend.ran)


@pytest.mark.asyncio
async def test_clean_with_yes_executes_aide() -> None:
    backend = FakeBackend(debsums_output="", exit_code=0, root=True)
    result = await run_guarded_baseline(
        backend,
        "aide",
        yes=True,
        changed_paths=["/usr/bin/sudo"],
    )
    assert not result.plan.blocked
    assert result.executed
    assert any(cmd[0] == "aide" for cmd in backend.ran)
