"""Runner tests for LocalBackend: timeout, non-zero exit, streaming."""

from __future__ import annotations

import pytest

from wardline.backends.local import LocalBackend, read_total_ram_mb


@pytest.fixture
def backend() -> LocalBackend:
    # Skip nice/ionice so argv assertions stay simple and CI stays fast.
    return LocalBackend(apply_priority=False)


@pytest.mark.asyncio
async def test_run_success_and_streaming(backend: LocalBackend) -> None:
    lines: list[tuple[str, str]] = []

    async def on_line(stream: str, line: str) -> None:
        lines.append((stream, line))

    result = await backend.run(
        ["printf", "%s\\n%s\\n", "alpha", "beta"],
        on_line=on_line,
    )
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "alpha" in result.stdout
    assert "beta" in result.stdout
    assert ("stdout", "alpha") in lines
    assert ("stdout", "beta") in lines


@pytest.mark.asyncio
async def test_nonzero_exit(backend: LocalBackend) -> None:
    result = await backend.run(["false"])
    assert result.exit_code != 0
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_timeout_kills_long_process(backend: LocalBackend) -> None:
    result = await backend.run(["sleep", "30"], timeout=0.3)
    assert result.timed_out is True
    assert result.duration_seconds < 5.0


@pytest.mark.asyncio
async def test_rejects_shell_string(backend: LocalBackend) -> None:
    with pytest.raises(ValueError, match="list\\[str\\]"):
        await backend.run("echo hi")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_which_and_exists(backend: LocalBackend) -> None:
    true_path = await backend.which("true")
    assert true_path is not None
    assert await backend.exists(true_path) is True
    assert await backend.exists("/nonexistent/wardline-path-xyz") is False


@pytest.mark.asyncio
async def test_host_info(backend: LocalBackend) -> None:
    info = await backend.host_info()
    assert info.hostname
    assert info.distro
    assert info.arch


@pytest.mark.asyncio
async def test_prefix_includes_nice_when_enabled() -> None:
    backend = LocalBackend(apply_priority=True)
    prefix = backend.prefix()
    # nice is essentially always present on Linux CI/lab hosts.
    if await backend.which("nice"):
        assert prefix[:3] == ["nice", "-n", "19"]


def test_read_total_ram_mb() -> None:
    ram = read_total_ram_mb()
    assert ram is None or ram > 0


@pytest.mark.asyncio
async def test_wrap_prepends_prefix() -> None:
    backend = LocalBackend(apply_priority=True)
    wrapped = backend.wrap(["true"])
    assert wrapped[-1] == "true"
    assert len(wrapped) >= 1
